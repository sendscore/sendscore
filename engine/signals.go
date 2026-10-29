package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/sendscore/sendscore/verdict"
)

// Content signals with a factual basis. There is deliberately no list of
// "spam words": mailbox providers filter on reputation, authentication, and
// engagement, and a word list would flag ordinary copy while claiming to
// know a filter's decision.

const (
	subjectCutoff          = 70 // characters a phone inbox typically shows
	imageOnlyOneChars      = 50
	imageOnlyManyChars     = 200
	maxBlocklistDomains    = 100
	blocklistConcurrency   = 8
	blocklistLookupTimeout = 4 * time.Second
	blocklistDeadline      = 20 * time.Second
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
	if subj == "" {
		r.add(verdict.Check{
			ID: "content.subject", Category: verdict.Content, Status: verdict.Fail,
			Title: "The subject line is empty",
			Fix:   &verdict.Fix{Who: verdict.FixedByYou, Text: "Write a subject line."},
		})
		return
	}
	// Each issue completes the sentence "The subject line ...".
	var issues []string
	if n > subjectCutoff {
		issues = append(issues, fmt.Sprintf("runs %d characters, past the %d a phone shows", n, subjectCutoff))
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
		issues = append(issues, "is written in capitals")
	}
	if bangs := strings.Count(subj, "!"); bangs >= 2 {
		issues = append(issues, fmt.Sprintf("has %d exclamation marks", bangs))
	}
	ev := map[string]any{"subject": subj, "characters": n}
	if len(issues) == 0 {
		r.add(verdict.Check{ID: "content.subject", Category: verdict.Content, Status: verdict.Pass, Title: "The subject line reads cleanly", Evidence: ev})
		return
	}
	ev["issues"] = issues
	r.add(verdict.Check{
		ID: "content.subject", Category: verdict.Content, Status: verdict.Warn,
		Title:    "The subject line " + joinAnd(issues),
		Evidence: ev,
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Shorten the subject, use sentence case, and keep to one exclamation mark at most."},
	})
}

// joinAnd joins phrases as "a", "a and b", or "a, b, and c".
func joinAnd(items []string) string { return joinList(items, "and") }

// joinList joins phrases with a conjunction and the serial comma.
func joinList(items []string, conj string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " " + conj + " " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + ", " + conj + " " + items[len(items)-1]
}

// checkPreheader looks at what an inbox shows next to the subject: the
// first text in the message, including hidden preheader text.
func (r *run) checkPreheader() {
	preview := collapse(r.msg.Text)
	if r.msg.HTML != "" {
		preview = r.parsed.Text
	}
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
	// Footer blocks (unsubscribe, address, and consent lines) are left out:
	// every bulk platform adds one, so they say nothing about the issue.
	chars := len([]rune(r.parsed.Body))
	content := 0
	for _, im := range r.parsed.Images {
		if !im.Pixel && !im.Hidden {
			content++
		}
	}
	ev := r.noteLimit(map[string]any{"text_characters": chars, "images": content})
	// Image-only means almost no words around the pictures: a single image
	// with next to no text, or several images with only a line or two. A
	// photo with a paragraph under it is an ordinary newsletter.
	imageOnly := (content == 1 && chars < imageOnlyOneChars) || (content >= 2 && chars < imageOnlyManyChars)
	if imageOnly {
		r.add(verdict.Check{
			ID: "content.text_ratio", Category: verdict.Content, Status: verdict.Warn,
			Title:    fmt.Sprintf("Mostly images, with %s and only %d characters of text outside the footer", plural(content, "image"), chars),
			Detail:   "Many readers have images off, so they see an almost empty email, and filters look harder at image-only mail.",
			Evidence: ev,
			Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Put the message in text, and use images to support it."},
		})
		return
	}
	r.add(r.partial(verdict.Check{ID: "content.text_ratio", Category: verdict.Content, Status: verdict.Pass, Title: "The message carries real text", Evidence: ev}))
}

func (r *run) checkShorteners() {
	var found set
	for _, l := range r.parsed.Links {
		if h := linkHost(l.Href); shorteners[h] {
			found.add(l.Href)
		}
	}
	if len(found.items) == 0 {
		r.add(r.partial(verdict.Check{ID: "content.shorteners", Category: verdict.Content, Status: verdict.Pass, Title: "No link shorteners"}))
		return
	}
	ev := map[string]any{}
	capped(ev, "links", found.items)
	r.add(verdict.Check{
		ID: "content.shorteners", Category: verdict.Content, Status: verdict.Warn,
		Title:    fmt.Sprintf("%s through a URL shortener", plural(len(found.items), "link")),
		Detail:   "Shorteners hide where a link goes, and filters treat them with suspicion because spammers use them.",
		Evidence: r.noteLimit(ev),
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Link to the real address instead."},
	})
}

// set is a list of distinct strings in the order first seen.
type set struct {
	seen  map[string]bool
	items []string
}

func (s *set) add(v string) {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if !s.seen[v] {
		s.seen[v] = true
		s.items = append(s.items, v)
	}
}

// Click tracking hosts of common email platforms. Their links name the real
// destination in the text and go through the tracker, which is expected.
var trackingSuffixes = []string{
	"list-manage.com", "mcusercontent.com", "convertkit-mail.com", "convertkit-mail2.com",
	"ck.page", "kit.com", "beehiiv.com", "mlsend.com", "mailerlite.com", "sendgrid.net",
	"mailgun.org", "rs6.net", "hubspotlinks.com", "substack.com", "buttondown.email",
	"ghost.io", "klclick.com", "klclick1.com", "ct.sendgrid.net", "awstrack.me",
}

func isTracker(host string) bool {
	for _, t := range trackingSuffixes {
		if host == t || strings.HasSuffix(host, "."+t) {
			return true
		}
	}
	return false
}

// Paths and first host labels that mark a click tracking redirect on the
// sender's own domain, such as email.mg.example.com/c/abc or
// url1234.example.com/ls/click.
var (
	trackingPath  = regexp.MustCompile(`(?i)^/(c|e|l|r|t|ls/click|wf/click|track/click|click|cl0|redirect|link|links)(/|$)`)
	trackingLabel = regexp.MustCompile(`(?i)^(click|clicks|email|emails|e|em|link|links|track|tracking|trk|t|go|r|mail|news|newsletter|url\d*)$`)
)

// ownTracker reports whether a link goes through a click tracking redirect
// on a subdomain of the sender's own domain. Both the subdomain and a
// tracking label or path are required, so a link to the sender's main
// site is still compared with its text.
func (r *run) ownTracker(href string) bool {
	if r.fromDom == "" {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	org := orgDomain(r.fromDom)
	if host == org || !strings.HasSuffix(host, "."+org) {
		return false
	}
	first, _, _ := strings.Cut(host, ".")
	return trackingLabel.MatchString(first) || trackingPath.MatchString(u.EscapedPath())
}

// checkLinkTextMismatch flags a link whose own text is a web address on one
// domain while the link goes to another. Links through a known click
// tracking host are allowed, and so are links through the issue's own
// tracking domain, recognised as the one domain carrying at least three
// links and more than half of them, or as a tracking subdomain of the
// sender's own domain. Every rule is deterministic.
func (r *run) checkLinkTextMismatch() {
	counts := map[string]int{}
	for _, l := range r.parsed.Links {
		if h := linkHost(l.Href); h != "" {
			counts[orgDomain(h)]++
		}
	}
	tracker := ""
	for h, n := range counts {
		if n >= 3 && n*2 > len(r.parsed.Links) {
			tracker = h // at most one domain can hold more than half
		}
	}
	var bad []map[string]string
	for _, l := range r.parsed.Links {
		shown := looksLikeDomain(l.Words)
		target := linkHost(l.Href)
		if shown == "" || target == "" {
			continue
		}
		if orgDomain(shown) == orgDomain(target) || orgDomain(target) == tracker || isTracker(target) || r.ownTracker(l.Href) {
			continue
		}
		bad = append(bad, map[string]string{"text": l.Words, "href": l.Href})
	}
	if len(bad) == 0 {
		r.add(r.partial(verdict.Check{ID: "content.link_text", Category: verdict.Content, Status: verdict.Pass, Title: "Links go where their text says"}))
		return
	}
	ev := map[string]any{}
	capped(ev, "links", bad)
	r.add(verdict.Check{
		ID: "content.link_text", Category: verdict.Content, Status: verdict.Warn,
		Title:    fmt.Sprintf("%s that show one address and go to another", plural(len(bad), "link")),
		Detail:   "Link text that names one domain while the link goes to another is a phishing signal to filters and readers.",
		Evidence: r.noteLimit(ev),
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Make the link text match the destination, or use words instead of an address."},
	})
}

func (r *run) checkActiveContent() {
	found := append([]string{}, r.parsed.Active...)
	for _, a := range r.msg.Attachments {
		found = append(found, "attachment "+a)
	}
	ev := map[string]any{}
	capped(ev, "found", found)
	if len(found) > maxEvidenceItems {
		found = append(found[:maxEvidenceItems:maxEvidenceItems], fmt.Sprintf("%d more", len(found)-maxEvidenceItems))
	}
	if len(found) == 0 {
		r.add(verdict.Check{ID: "content.active", Category: verdict.Content, Status: verdict.Pass, Title: "No scripts, forms, embeds, or attachments"})
		return
	}
	r.add(verdict.Check{
		ID: "content.active", Category: verdict.Content, Status: verdict.Warn,
		Title:    "Contains " + joinAnd(found),
		Detail:   "Mail clients strip scripts, forms, and embeds, and filters are wary of them and of attachments in bulk mail.",
		Evidence: ev,
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Link to a web page for anything interactive, and link to files instead of attaching them."},
	})
}

// checkBlocklists looks the domains of every link and image up on the
// configured domain blocklists. It only passes when every list answered for
// every domain, and it proves each list answers by looking up the list's
// own test domain first. Nothing is looked up unless lists are configured:
// the free public zones are for non-commercial use only.
func (r *run) checkBlocklists() {
	lists := r.opts.Blocklists
	if len(lists) == 0 {
		r.add(skipped("content.blocklists", verdict.Content, "Link domains not looked up",
			"Blocklist lookups are off. Set a Spamhaus DQS key, or turn on the free public lists for non-commercial use."))
		return
	}
	// Hosts are looked up as ASCII DNS names. One that cannot be written as
	// one (a bad IDN, or a label over 63 bytes) is reported as not checked:
	// a resolver refuses such a name locally, which would read as not listed.
	var all, invalid set
	addHost := func(u string) {
		h := linkHost(u)
		if h == "" || net.ParseIP(h) != nil {
			return
		}
		ascii, ok := dnsName(h)
		if !ok {
			invalid.add(h)
			return
		}
		all.add(orgDomain(ascii))
	}
	for _, l := range r.parsed.Links {
		addHost(l.Href)
	}
	for _, im := range r.parsed.Images {
		addHost(im.Src)
	}
	domains := all.items
	sort.Strings(domains)
	sort.Strings(invalid.items)
	if len(domains) == 0 && len(invalid.items) == 0 {
		r.add(r.partial(verdict.Check{ID: "content.blocklists", Category: verdict.Content, Status: verdict.Info, Title: "No link domains to look up"}))
		return
	}
	var unchecked []string
	if len(domains) > maxBlocklistDomains {
		unchecked = domains[maxBlocklistDomains:]
		domains = domains[:maxBlocklistDomains]
	}
	// The query name must also fit, with the list's zone, in 253 bytes.
	for _, bl := range lists {
		kept := domains[:0:0]
		for _, d := range domains {
			if len(d)+1+len(bl.Zone) > 253 {
				invalid.add(d)
				continue
			}
			kept = append(kept, d)
		}
		domains = kept
	}

	ctx, cancel := context.WithTimeout(r.ctx, blocklistDeadline)
	defer cancel()

	type job struct {
		list   Blocklist
		domain string
		test   bool
	}
	var jobs []job
	for _, bl := range lists {
		jobs = append(jobs, job{list: bl, domain: bl.TestDomain, test: true})
		for _, d := range domains {
			jobs = append(jobs, job{list: bl, domain: d})
		}
	}
	results := make([]blResult, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, blocklistConcurrency)
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = r.queryBlocklist(ctx, j.list, j.domain)
		}()
	}
	wg.Wait()

	if errors.Is(r.ctx.Err(), context.Canceled) {
		r.add(skipped("content.blocklists", verdict.Content, "Link domains not looked up", "The check was cancelled."))
		return
	}

	var listed []map[string]string
	var problems, hit set
	for i, j := range jobs {
		res := results[i]
		switch {
		case res.offline:
			r.add(skipped("content.blocklists", verdict.Content, "Link domains not looked up", "Offline: DNS lookups are disabled."))
			return
		case j.test && res.state != blListed:
			problems.add(j.list.Name + " did not answer its test lookup (" + res.describe() + ")")
		case !j.test && res.state == blListed:
			listed = append(listed, map[string]string{"domain": j.domain, "list": j.list.Name, "answer": res.answer})
			hit.add(j.domain)
		case !j.test && res.state != blClear:
			problems.add(j.list.Name + " could not check " + j.domain + " (" + res.describe() + ")")
		}
	}
	names := make([]string, 0, len(lists))
	for _, bl := range lists {
		names = append(names, bl.Name)
	}
	ev := map[string]any{"lists": names}
	capped(ev, "domains", domains)
	if len(unchecked) > 0 {
		capped(ev, "not_checked", unchecked)
	}
	if len(invalid.items) > 0 {
		capped(ev, "not_valid", invalid.items)
	}
	if len(problems.items) > 0 {
		capped(ev, "problems", problems.items)
	}
	ev = r.noteLimit(ev)
	if len(listed) > 0 {
		capped(ev, "listed", listed)
		shown := hit.items
		if len(shown) > maxEvidenceItems {
			shown = append(shown[:maxEvidenceItems:maxEvidenceItems], fmt.Sprintf("%d more", len(hit.items)-maxEvidenceItems))
		}
		r.add(verdict.Check{
			ID: "content.blocklists", Category: verdict.Content, Status: verdict.Fail,
			Title:    "Links to a blocklisted domain (" + strings.Join(shown, ", ") + ")",
			Detail:   "Filters reject or junk mail that links to domains on these lists, whatever else the message gets right.",
			Evidence: ev,
			Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Remove links to the listed domains, or ask the list to delist a domain you own."},
			Docs:     "https://www.spamhaus.org/blocklists/domain-blocklist/",
		})
		return
	}
	if len(problems.items) > 0 || len(unchecked) > 0 || len(invalid.items) > 0 {
		var reasons []string
		if len(problems.items) > 3 {
			reasons = append(reasons, strings.Join(problems.items[:3], "; ")+fmt.Sprintf("; and %d more lookups failed", len(problems.items)-3))
		} else if len(problems.items) > 0 {
			reasons = append(reasons, strings.Join(problems.items, "; "))
		}
		if len(unchecked) > 0 {
			reasons = append(reasons, fmt.Sprintf("%d more domains were not looked up (the limit is %d)", len(unchecked), maxBlocklistDomains))
		}
		if len(invalid.items) > 0 {
			reasons = append(reasons, fmt.Sprintf("%s could not be looked up because %s not valid DNS names",
				plural(len(invalid.items), "link domain"), map[bool]string{true: "it is", false: "they are"}[len(invalid.items) == 1]))
		}
		reason := strings.Join(reasons, "; ")
		c := skipped("content.blocklists", verdict.Content, "Not every link domain could be looked up", strings.ToUpper(reason[:1])+reason[1:]+".")
		c.Evidence = ev
		r.add(c)
		return
	}
	r.add(r.partial(verdict.Check{
		ID: "content.blocklists", Category: verdict.Content, Status: verdict.Pass,
		Title:    fmt.Sprintf("No link domain is on %s (%s checked)", joinList(names, "or"), plural(len(domains), "domain")),
		Evidence: ev,
	}))
}

// dnsName converts a host to the ASCII form DNS uses, and reports false
// when it cannot be one: a failed IDN conversion, an empty label, a label
// over 63 bytes, or a name over 253 bytes.
func dnsName(host string) (string, bool) {
	a, err := idna.Lookup.ToASCII(strings.TrimSuffix(host, "."))
	if err != nil || a == "" || len(a) > 253 {
		return "", false
	}
	for _, label := range strings.Split(a, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
	}
	return strings.ToLower(a), true
}

type blState int

const (
	blClear blState = iota
	blListed
	blRefused
	blFailed
)

type blResult struct {
	state   blState
	answer  string
	detail  string
	offline bool
}

func (b blResult) describe() string {
	switch b.state {
	case blClear:
		return "not listed"
	case blListed:
		return "listed"
	case blRefused:
		return "refused, " + b.detail
	}
	return b.detail
}

func (r *run) queryBlocklist(ctx context.Context, bl Blocklist, domain string) blResult {
	ctx, cancel := context.WithTimeout(ctx, blocklistLookupTimeout)
	defer cancel()
	ips, err := r.lookupA(ctx, domain+"."+bl.Zone)
	if err != nil {
		if errors.Is(err, ErrOffline) {
			return blResult{offline: true}
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return blResult{state: blClear}
		}
		if ctx.Err() != nil {
			return blResult{state: blFailed, detail: "timed out"}
		}
		return blResult{state: blFailed, detail: "lookup failed"}
	}
	for _, ip := range ips {
		if reason := bl.refusal(ip); reason != "" {
			return blResult{state: blRefused, answer: ip.String(), detail: reason}
		}
		if bl.listed(ip) {
			return blResult{state: blListed, answer: ip.String()}
		}
	}
	return blResult{state: blFailed, answer: fmt.Sprint(ips), detail: "unexpected answer"}
}

// lookupA asks for IPv4 addresses only, which is all a blocklist answers
// with, when the resolver supports it.
func (r *run) lookupA(ctx context.Context, host string) ([]net.IP, error) {
	if ip4, ok := r.res.(interface {
		LookupIP(context.Context, string, string) ([]net.IP, error)
	}); ok {
		return ip4.LookupIP(ctx, "ip4", host)
	}
	addrs, err := r.res.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			out = append(out, v4)
		}
	}
	return out, nil
}

func linkHost(u string) string {
	p, err := url.Parse(strings.TrimSpace(u))
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") {
		return ""
	}
	return strings.ToLower(p.Hostname())
}

// File extensions and names that look like domains in link text. Some
// (.zip, .mov, .md) are real top-level domains, but in a newsletter they are
// far more often a file or a technology name.
var notDomains = map[string]bool{
	"js": true, "ts": true, "py": true, "rb": true, "go": true, "rs": true, "sh": true,
	"md": true, "txt": true, "pdf": true, "doc": true, "docx": true, "xls": true,
	"xlsx": true, "csv": true, "zip": true, "mov": true, "mp4": true, "mp3": true,
	"jpg": true, "jpeg": true, "png": true, "gif": true, "svg": true, "webp": true,
	"html": true, "json": true,
}

// looksLikeDomain returns the host named by link text such as
// "example.com/path", "www.example.com", or "https://example.com", or ""
// for words, file names, and technology names like "Node.js".
func looksLikeDomain(text string) string {
	t := strings.ToLower(strings.TrimSpace(text))
	if t == "" || strings.ContainsAny(t, " \t") {
		return ""
	}
	explicit := strings.Contains(t, "://") || strings.HasPrefix(t, "www.")
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, err := url.Parse(t)
	if err != nil || u.Hostname() == "" || net.ParseIP(u.Hostname()) != nil {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	suffix, icann := publicsuffix.PublicSuffix(h)
	if !icann || suffix == h {
		return ""
	}
	if !explicit && notDomains[suffix] && strings.Trim(u.Path, "/") == "" {
		return ""
	}
	return h
}
