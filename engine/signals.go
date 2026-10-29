package engine

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/sendscore/sendscore/verdict"
)

// Content signals with a factual basis. There is deliberately no list of
// "spam words": mailbox providers filter on reputation, authentication, and
// engagement, and a word list would flag ordinary copy while claiming to
// know a filter's decision.

const (
	subjectCutoff   = 70 // characters a phone inbox typically shows
	imageOnlyChars  = 300
	maxBlocklistDNS = 30
)

// URL shorteners hide where a link goes, which filters treat with suspicion.
var shorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true, "ow.ly": true,
	"is.gd": true, "buff.ly": true, "rebrand.ly": true, "cutt.ly": true, "shorturl.at": true,
	"tiny.cc": true, "rb.gy": true, "bl.ink": true, "s.id": true, "t.ly": true, "v.gd": true,
}

// What a client shows as the preview when an issue has no preview text.
var boilerplateOpeners = []string{
	"view in browser", "view this email", "view online", "view it online", "web version",
	"view as a web page", "view as webpage", "having trouble viewing", "if you can't see",
	"if you cannot see", "click here to view", "open in browser", "read online",
}

func (r *run) checkSubject() {
	subj := strings.TrimSpace(r.msg.get("Subject"))
	n := len([]rune(subj))
	var issues []string
	if subj == "" {
		r.add(verdict.Check{
			ID: "content.subject", Category: verdict.Content, Status: verdict.Fail,
			Title: "The subject line is empty",
			Fix:   &verdict.Fix{Who: verdict.FixedByYou, Text: "Write a subject line."},
		})
		return
	}
	if n > subjectCutoff {
		issues = append(issues, fmt.Sprintf("%d characters, so phones cut it off after about %d", n, subjectCutoff))
	}
	letters, upper := 0, 0
	for _, c := range subj {
		if unicode.IsLetter(c) {
			letters++
			if unicode.IsUpper(c) {
				upper++
			}
		}
	}
	if letters >= 10 && upper*10 >= letters*8 {
		issues = append(issues, "written in capitals")
	}
	if strings.Count(subj, "!") >= 2 {
		issues = append(issues, fmt.Sprintf("%d exclamation marks", strings.Count(subj, "!")))
	}
	ev := map[string]any{"subject": subj, "characters": n}
	if len(issues) == 0 {
		r.add(verdict.Check{ID: "content.subject", Category: verdict.Content, Status: verdict.Pass, Title: "The subject line reads cleanly", Evidence: ev})
		return
	}
	ev["issues"] = issues
	r.add(verdict.Check{
		ID: "content.subject", Category: verdict.Content, Status: verdict.Warn,
		Title:    "The subject line is " + strings.Join(issues, ", and "),
		Evidence: ev,
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Shorten the subject, use sentence case, and keep to one exclamation mark at most."},
	})
}

// checkPreheader looks at what an inbox shows next to the subject: the
// first text in the message, including hidden preheader text.
func (r *run) checkPreheader() {
	text := r.msg.Text
	if r.msg.HTML != "" {
		text = visibleText(r.msg.HTML)
	}
	preview := strings.Join(strings.Fields(text), " ")
	if len([]rune(preview)) > 100 {
		preview = string([]rune(preview)[:100])
	}
	low := strings.ToLower(preview)
	ev := map[string]any{"preview": preview}
	if preview == "" {
		r.add(verdict.Check{ID: "content.preheader", Category: verdict.Content, Status: verdict.Warn, Title: "There is no preview text", Evidence: ev,
			Fix: &verdict.Fix{Who: verdict.FixedByYou, Text: "Add preview text (sometimes called a preheader) in your email platform."}})
		return
	}
	for _, b := range boilerplateOpeners {
		if strings.HasPrefix(low, b) {
			r.add(verdict.Check{
				ID: "content.preheader", Category: verdict.Content, Status: verdict.Warn,
				Title:    "The inbox preview will show \"" + truncate(preview, 40) + "\"",
				Detail:   "With no preview text, inboxes show the first words of the email, which here is template boilerplate.",
				Evidence: ev,
				Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Add preview text (sometimes called a preheader) in your email platform."},
			})
			return
		}
	}
	r.add(verdict.Check{ID: "content.preheader", Category: verdict.Content, Status: verdict.Pass, Title: "The inbox preview starts with real text", Evidence: ev})
}

func (r *run) checkImageOnly() {
	if r.msg.HTML == "" {
		r.add(verdict.Check{ID: "content.text_ratio", Category: verdict.Content, Status: verdict.Info, Title: "Plain text message"})
		return
	}
	chars := len([]rune(strings.Join(strings.Fields(visibleText(r.msg.HTML)), " ")))
	content := 0
	for _, im := range r.parsed.Images {
		if !im.Pixel && !im.Hidden {
			content++
		}
	}
	ev := map[string]any{"text_characters": chars, "images": content}
	if content > 0 && chars < imageOnlyChars {
		r.add(verdict.Check{
			ID: "content.text_ratio", Category: verdict.Content, Status: verdict.Warn,
			Title:    fmt.Sprintf("Mostly images, with %s and only %d characters of text", plural(content, "image"), chars),
			Detail:   "Many readers have images off, so they see an almost empty email, and filters look harder at image-only mail.",
			Evidence: ev,
			Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Put the message in text, and use images to support it."},
		})
		return
	}
	r.add(verdict.Check{ID: "content.text_ratio", Category: verdict.Content, Status: verdict.Pass, Title: "The message carries real text", Evidence: ev})
}

func (r *run) checkShorteners() {
	var found []string
	for _, l := range r.parsed.Links {
		if h := linkHost(l.Href); shorteners[h] {
			found = appendUnique(found, l.Href)
		}
	}
	if len(found) == 0 {
		r.add(verdict.Check{ID: "content.shorteners", Category: verdict.Content, Status: verdict.Pass, Title: "No link shorteners"})
		return
	}
	r.add(verdict.Check{
		ID: "content.shorteners", Category: verdict.Content, Status: verdict.Warn,
		Title:    fmt.Sprintf("%s through a URL shortener", plural(len(found), "link")),
		Detail:   "Shorteners hide where a link goes, and filters treat them with suspicion because spammers use them.",
		Evidence: map[string]any{"links": found},
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Link to the real address instead."},
	})
}

// checkLinkTextMismatch flags a link whose visible text is a web address on
// one domain while the link goes to another. Click tracking sends every link
// through one domain, so links to the issue's most common host are allowed.
func (r *run) checkLinkTextMismatch() {
	counts := map[string]int{}
	for _, l := range r.parsed.Links {
		if h := linkHost(l.Href); h != "" {
			counts[orgDomain(h)]++
		}
	}
	tracker, best := "", 0
	for h, n := range counts {
		if n > best {
			tracker, best = h, n
		}
	}
	if best*2 < len(r.parsed.Links) {
		tracker = ""
	}
	var bad []map[string]string
	for _, l := range r.parsed.Links {
		shown := looksLikeDomain(l.Text)
		target := linkHost(l.Href)
		if shown == "" || target == "" {
			continue
		}
		if orgDomain(shown) == orgDomain(target) || orgDomain(target) == tracker {
			continue
		}
		bad = append(bad, map[string]string{"text": l.Text, "href": l.Href})
	}
	if len(bad) == 0 {
		r.add(verdict.Check{ID: "content.link_text", Category: verdict.Content, Status: verdict.Pass, Title: "Links go where their text says"})
		return
	}
	r.add(verdict.Check{
		ID: "content.link_text", Category: verdict.Content, Status: verdict.Warn,
		Title:    fmt.Sprintf("%s that show one address and go to another", plural(len(bad), "link")),
		Detail:   "Link text that names one domain while the link goes to another is a phishing signal to filters and readers.",
		Evidence: map[string]any{"links": bad},
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Make the link text match the destination, or use words instead of an address."},
	})
}

func (r *run) checkActiveContent() {
	found := append([]string{}, r.parsed.Active...)
	for _, a := range r.msg.Attachments {
		found = append(found, "attachment "+a)
	}
	if len(found) == 0 {
		r.add(verdict.Check{ID: "content.active", Category: verdict.Content, Status: verdict.Pass, Title: "No scripts, forms, embeds, or attachments"})
		return
	}
	r.add(verdict.Check{
		ID: "content.active", Category: verdict.Content, Status: verdict.Warn,
		Title:    "Contains " + strings.Join(found, ", "),
		Detail:   "Mail clients strip scripts, forms, and embeds, and filters are wary of them and of attachments in bulk mail.",
		Evidence: map[string]any{"found": found},
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Link to a web page for anything interactive, and link to files instead of attaching them."},
	})
}

// Domain blocklists queried over DNS. A listing answers with an address in
// the list's range; some answers mean the query itself was refused, which
// Spamhaus does for queries through large public resolvers.
var blocklists = []struct {
	name, zone string
	listed     func(ip net.IP) bool
	refused    func(ip net.IP) bool
}{
	{
		name: "Spamhaus DBL", zone: "dbl.spamhaus.org",
		listed:  func(ip net.IP) bool { v := ip.To4(); return v != nil && v[0] == 127 && v[1] == 0 && v[2] == 1 },
		refused: func(ip net.IP) bool { v := ip.To4(); return v != nil && v[0] == 127 && v[1] == 255 && v[2] == 255 },
	},
	{
		name: "SURBL", zone: "multi.surbl.org",
		listed: func(ip net.IP) bool {
			v := ip.To4()
			return v != nil && v[0] == 127 && v[1] == 0 && v[2] == 0 && v[3] > 1
		},
		refused: func(ip net.IP) bool { v := ip.To4(); return v != nil && v.Equal(net.IPv4(127, 0, 0, 1).To4()) },
	},
}

func (r *run) checkBlocklists() {
	var domains []string
	for _, l := range r.parsed.Links {
		if h := linkHost(l.Href); h != "" {
			domains = appendUnique(domains, orgDomain(h))
		}
	}
	for _, im := range r.parsed.Images {
		if h := linkHost(im.Src); h != "" {
			domains = appendUnique(domains, orgDomain(h))
		}
	}
	sort.Strings(domains)
	if len(domains) == 0 {
		r.add(verdict.Check{ID: "content.blocklists", Category: verdict.Content, Status: verdict.Info, Title: "No link domains to look up"})
		return
	}
	if len(domains) > maxBlocklistDNS {
		domains = domains[:maxBlocklistDNS]
	}

	var listed []map[string]string
	refused := map[string]bool{}
	answered := 0
	for _, d := range domains {
		for _, bl := range blocklists {
			addrs, err := r.res.LookupIPAddr(r.ctx, d+"."+bl.zone)
			if err != nil {
				if errors.Is(err, ErrOffline) {
					r.add(skipped("content.blocklists", verdict.Content, "Link domains not looked up", "Offline: DNS lookups are disabled."))
					return
				}
				if lookupFailed(err) == "" {
					answered++ // not listed
				}
				continue
			}
			for _, a := range addrs {
				switch {
				case bl.refused(a.IP):
					refused[bl.name] = true
				case bl.listed(a.IP):
					listed = append(listed, map[string]string{"domain": d, "list": bl.name, "answer": a.IP.String()})
					answered++
				}
			}
		}
	}
	ev := map[string]any{"domains": domains, "lists": []string{"Spamhaus DBL", "SURBL"}}
	if len(listed) > 0 {
		ev["listed"] = listed
		names := []string{}
		for _, l := range listed {
			names = appendUnique(names, l["domain"])
		}
		r.add(verdict.Check{
			ID: "content.blocklists", Category: verdict.Content, Status: verdict.Fail,
			Title:    "Links to a blocklisted domain: " + strings.Join(names, ", "),
			Detail:   "Filters reject or junk mail that links to domains on these lists, whatever else the message gets right.",
			Evidence: ev,
			Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Remove links to the listed domains, or ask the list to delist a domain you own."},
			Docs:     "https://www.spamhaus.org/blocklists/domain-blocklist/",
		})
		return
	}
	if answered == 0 {
		reason := "The blocklists did not answer."
		if len(refused) > 0 {
			reason = "The blocklists refused the query, which they do for large public DNS resolvers. Use a resolver of your own to run this check."
		}
		r.add(skipped("content.blocklists", verdict.Content, "Link domains not looked up", reason))
		return
	}
	r.add(verdict.Check{
		ID: "content.blocklists", Category: verdict.Content, Status: verdict.Pass,
		Title:    fmt.Sprintf("No link domain is on Spamhaus DBL or SURBL (%d checked)", len(domains)),
		Evidence: ev,
	})
}

func linkHost(u string) string {
	p, err := url.Parse(strings.TrimSpace(u))
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") {
		return ""
	}
	return strings.ToLower(p.Hostname())
}

// looksLikeDomain returns the host named by link text such as
// "example.com/path" or "https://example.com", or "" for ordinary words.
func looksLikeDomain(text string) string {
	t := strings.ToLower(strings.TrimSpace(text))
	if t == "" || strings.ContainsAny(t, " \t") {
		return ""
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	h := linkHost(t)
	dot := strings.LastIndex(h, ".")
	if dot <= 0 || dot == len(h)-1 {
		return ""
	}
	for _, c := range h[dot+1:] {
		if !unicode.IsLetter(c) {
			return ""
		}
	}
	return h
}
