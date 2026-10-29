package engine

import (
	"strings"

	"github.com/sendscore/sendscore/verdict"
)

// listUnsubURIs returns the URIs in List-Unsubscribe, in order.
func (r *run) listUnsubURIs() []string {
	var out []string
	for _, part := range strings.Split(r.msg.Header.Get("List-Unsubscribe"), ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "<") && strings.HasSuffix(part, ">") {
			out = append(out, strings.TrimSpace(part[1:len(part)-1]))
		}
	}
	return out
}

func (r *run) unsubscribe() {
	uris := r.listUnsubURIs()
	https := ""
	mailto := false
	for _, u := range uris {
		l := strings.ToLower(u)
		if strings.HasPrefix(l, "https:") && https == "" {
			https = u
		}
		if strings.HasPrefix(l, "mailto:") {
			mailto = true
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

	r.checkUnsubSigned(len(uris) > 0, post != "")
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
	if found == "" && strings.Contains(strings.ToLower(r.msg.Text), "unsubscribe") {
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
