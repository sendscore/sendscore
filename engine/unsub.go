package engine

import (
	"strings"

	"github.com/sendscore/sendscore/verdict"
)

// listUnsubURIs returns the URIs in List-Unsubscribe, in order. RFC 2369
// encloses each in angle brackets, so a comma inside one is part of the URI.
// Comments in parentheses are ignored, and so is whitespace inside a URI.
func (r *run) listUnsubURIs() []string {
	return parseListURIs(r.msg.Header.Get("List-Unsubscribe"))
}

func parseListURIs(h string) []string {
	var out []string
	depth := 0
	for i := 0; i < len(h); i++ {
		switch c := h[i]; {
		case c == '\\' && depth > 0:
			i++
		case c == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case c == '<' && depth == 0:
			end := strings.IndexByte(h[i:], '>')
			if end < 0 {
				return out
			}
			uri := strings.Join(strings.Fields(h[i+1:i+end]), "")
			if uri != "" {
				out = append(out, uri)
			}
			i += end
		}
	}
	return out
}

func (r *run) unsubscribe() {
	uris := r.listUnsubURIs()
	present := strings.TrimSpace(r.msg.Header.Get("List-Unsubscribe")) != ""
	https := ""
	mailto, http := false, false
	for _, u := range uris {
		l := strings.ToLower(u)
		if strings.HasPrefix(l, "https:") && https == "" {
			https = u
		}
		if strings.HasPrefix(l, "mailto:") {
			mailto = true
		}
		if strings.HasPrefix(l, "http:") {
			http = true
		}
	}
	r.fp.ListUnsubscribe = len(uris) > 0

	c := verdict.Check{ID: "unsub.header", Category: verdict.Unsub, Docs: docsGmail, Evidence: map[string]any{"uris": uris}}
	switch {
	case https != "":
		c.Status, c.Title = verdict.Pass, "List-Unsubscribe has an https link"
	case mailto:
		c.Status, c.Title = verdict.Warn, "List-Unsubscribe has only a mailto address"
		c.Detail = "One-click unsubscribe needs an https URL."
		c.Fix = &verdict.Fix{Who: verdict.FixedByProvider, Text: "Turn on one-click unsubscribe in your email platform."}
	case http:
		c.Status, c.Title = verdict.Fail, "List-Unsubscribe has an http link, not https"
		c.Detail = "Gmail and Yahoo require an https link for one-click unsubscribe."
		c.Fix = &verdict.Fix{Who: verdict.FixedByProvider, Text: "Ask your email platform to put an https unsubscribe link in List-Unsubscribe."}
	case len(uris) > 0:
		c.Status, c.Title = verdict.Fail, "List-Unsubscribe has no https link or mailto address"
		c.Fix = &verdict.Fix{Who: verdict.FixedByProvider, Text: "Ask your email platform to put an https unsubscribe link in List-Unsubscribe."}
	case present:
		c.Status, c.Title = verdict.Fail, "List-Unsubscribe has no link in angle brackets"
		c.Detail = "RFC 2369 requires each link to be enclosed in angle brackets, so receivers find none here."
		c.Fix = &verdict.Fix{Who: verdict.FixedByProvider, Text: "Ask your email platform to format List-Unsubscribe as <https://...>, with the link in angle brackets."}
	default:
		c.Status, c.Title = verdict.Fail, "No List-Unsubscribe header"
		c.Fix = &verdict.Fix{Who: verdict.FixedByProvider, Text: "Gmail and Yahoo require List-Unsubscribe on bulk mail. Turn on one-click unsubscribe in your email platform."}
	}
	r.add(c)

	post := strings.TrimSpace(r.msg.Header.Get("List-Unsubscribe-Post"))
	oneClick := strings.EqualFold(post, "List-Unsubscribe=One-Click")
	r.fp.OneClick = oneClick && https != ""
	oc := verdict.Check{ID: "unsub.one_click", Category: verdict.Unsub, Docs: docsRFC8058, Evidence: map[string]any{"list_unsubscribe_post": post}}
	switch {
	case oneClick && https != "":
		oc.Status, oc.Title = verdict.Pass, "One-click unsubscribe is set up"
	case oneClick:
		oc.Status, oc.Title = verdict.Fail, "One-click is declared without an https link"
		oc.Fix = &verdict.Fix{Who: verdict.FixedByProvider, Text: "List-Unsubscribe must carry an https URL for one-click to work."}
	case post != "":
		oc.Status, oc.Title = verdict.Fail, "List-Unsubscribe-Post has the wrong value"
		oc.Detail = "It must be exactly List-Unsubscribe=One-Click."
		oc.Fix = &verdict.Fix{Who: verdict.FixedByProvider, Text: "Set List-Unsubscribe-Post to List-Unsubscribe=One-Click."}
	default:
		oc.Status, oc.Title = verdict.Fail, "No one-click unsubscribe"
		oc.Detail = "List-Unsubscribe-Post: List-Unsubscribe=One-Click is missing."
		oc.Fix = &verdict.Fix{Who: verdict.FixedByProvider, Text: "Turn on one-click unsubscribe (RFC 8058) in your email platform."}
	}
	r.add(oc)

	r.checkUnsubSigned(present, post != "")
}

// checkUnsubSigned: RFC 8058 requires a valid DKIM signature that covers
// both headers, or a forwarder could add them to someone else's message.
func (r *run) checkUnsubSigned(hasHeader, hasPost bool) {
	if !hasHeader {
		r.add(skipped("unsub.signed", verdict.Unsub, "Unsubscribe signing not checked", "There is no List-Unsubscribe header."))
		return
	}
	if r.fp.Auth["dkim"] == verdict.Skipped {
		r.add(skipped("unsub.signed", verdict.Unsub, "Unsubscribe signing not checked", "DKIM could not be verified."))
		return
	}
	for _, d := range r.dkim {
		if d.Result != "pass" {
			continue
		}
		covers := func(name string) bool {
			for _, k := range d.HeaderKeys {
				if strings.EqualFold(k, name) {
					return true
				}
			}
			return false
		}
		if covers("List-Unsubscribe") && (!hasPost || covers("List-Unsubscribe-Post")) {
			r.add(verdict.Check{
				ID: "unsub.signed", Category: verdict.Unsub, Status: verdict.Pass,
				Title:    "Unsubscribe headers are DKIM signed",
				Evidence: map[string]any{"signed_by": d.Domain},
				Docs:     docsRFC8058,
			})
			return
		}
	}
	r.add(verdict.Check{
		ID: "unsub.signed", Category: verdict.Unsub, Status: verdict.Fail,
		Title:  "Unsubscribe headers are not covered by a valid DKIM signature",
		Detail: "RFC 8058 requires the signature to cover List-Unsubscribe and List-Unsubscribe-Post.",
		Fix:    &verdict.Fix{Who: verdict.FixedByProvider, Text: "Your email platform must sign List-Unsubscribe and List-Unsubscribe-Post in its DKIM signature."},
		Docs:   docsRFC8058,
	})
}

// visibleUnsubscribe looks for an unsubscribe link people can see.
func (r *run) checkVisibleUnsub() {
	found := ""
	if r.parsed != nil {
		for _, l := range r.parsed.Links {
			t := strings.ToLower(l.Text + " " + l.Href)
			if strings.Contains(t, "unsubscribe") || strings.Contains(t, "opt out") || strings.Contains(t, "opt-out") {
				found = l.Href
				break
			}
		}
	}
	if found == "" && r.msg.HTML == "" && strings.Contains(strings.ToLower(r.msg.Text), "unsubscribe") {
		found = "(plain text)"
	}
	if found != "" {
		r.add(verdict.Check{
			ID: "unsub.visible", Category: verdict.Unsub, Status: verdict.Pass,
			Title: "Visible unsubscribe link", Evidence: map[string]any{"link": found},
		})
		return
	}
	r.add(verdict.Check{
		ID: "unsub.visible", Category: verdict.Unsub, Status: verdict.Warn,
		Title:  "No visible unsubscribe link found",
		Detail: "No link mentions unsubscribe or opt out. If yours uses other words, ignore this.",
		Fix:    &verdict.Fix{Who: verdict.FixedByYou, Text: "Add a clearly labelled unsubscribe link to the footer of your template."},
	})
}
