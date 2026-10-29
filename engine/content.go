package engine

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"

	"github.com/sendscore/sendscore/verdict"
)

type link struct {
	Href string
	// Text is what a reader sees, including the alt text of a linked image.
	Text string
	// Words is the link's own text, without alt text.
	Words string
}

type image struct {
	Src    string
	Alt    *string
	Pixel  bool
	Hidden bool
}

// Limits on what one message makes the checks examine. A real issue has a
// few dozen links; these stop a hostile one from costing more than that.
const (
	maxLinksExamined  = 2000
	maxImagesExamined = 2000
	maxEvidenceItems  = 20
	maxLinkHosts      = 200
)

type parsedHTML struct {
	Links  []link
	Images []image
	// LinksTotal and ImagesTotal count every link and image, including
	// those past the examination limits.
	LinksTotal, ImagesTotal int
	// Active lists elements a newsletter should not carry: scripts, forms,
	// and embedded frames or objects.
	Active []string
	// Text is the visible text: no tags, comments, styles, or scripts.
	Text string
	// Body is the visible text without footer blocks (unsubscribe,
	// address, and consent lines), which every bulk platform adds.
	Body string
	// Attrs holds the href, src, and alt values, where merge tags also
	// appear.
	Attrs string
}

func (p *parsedHTML) truncated() bool {
	return p.LinksTotal > len(p.Links) || p.ImagesTotal > len(p.Images)
}

// Block level elements. Text inside one is judged as one block when
// deciding what is footer.
var blockTags = map[string]bool{
	"p": true, "div": true, "td": true, "th": true, "tr": true, "table": true, "li": true,
	"ul": true, "ol": true, "br": true, "hr": true, "h1": true, "h2": true, "h3": true,
	"h4": true, "h5": true, "h6": true, "section": true, "footer": true, "header": true,
	"center": true, "blockquote": true, "body": true, "article": true,
}

// Phrases that mark a block as the platform footer rather than the issue.
var footerMarkers = []string{
	"unsubscribe", "opt out", "opt-out", "preferences", "manage your subscription",
	"you are receiving", "you're receiving", "you received this", "you are subscribed",
	"you signed up", "you subscribed", "why did i get this", "no longer wish",
	"copyright", "\u00a9", "(c) 20", "all rights reserved", "our mailing address", "mailing address is",
	"update your profile", "forward to a friend", "add us to your address book",
}

// Phrases that mark a block of template boilerplate at the top.
var headerMarkers = []string{
	"view in browser", "view this email", "view online", "view it online", "web version",
	"view as a web page", "having trouble viewing", "open in browser", "read online",
}

// Footer limits. The footer is the run of blocks at the end of the message
// from the first one with a footer phrase, as long as that run is short; a
// long block that mentions copyright is more likely the issue itself.
const (
	maxFooterChars = 1000
	maxFooterBlock = 500
)

func hasAny(block string, phrases []string) bool {
	if len(block) > 4*maxFooterBlock || len([]rune(block)) > maxFooterBlock {
		return false
	}
	l := strings.ToLower(block)
	for _, m := range phrases {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// bodyText joins the blocks that are neither the footer at the end nor
// boilerplate or footer lines elsewhere.
func bodyText(blocks []string) string {
	cut, size := len(blocks), 0
	for i := len(blocks) - 1; i >= 0; i-- {
		size += len([]rune(blocks[i]))
		if size > maxFooterChars {
			break
		}
		if hasAny(blocks[i], footerMarkers) {
			cut = i
		}
	}
	var kept []string
	for _, b := range blocks[:cut] {
		if !hasAny(b, footerMarkers) && !hasAny(b, headerMarkers) {
			kept = append(kept, b)
		}
	}
	return strings.Join(kept, " ")
}

// stripInvisible drops the zero width and other invisible characters that
// templates repeat to pad out a preheader. They render as nothing, so they
// are not text.
func stripInvisible(s string) string {
	if !strings.ContainsFunc(s, isInvisible) {
		return s
	}
	return strings.Map(func(c rune) rune {
		if isInvisible(c) {
			return -1
		}
		return c
	}, s)
}

func isInvisible(c rune) bool {
	switch {
	case c == 0x00AD, c == 0x034F, c == 0x061C, c == 0x115F, c == 0x1160,
		c == 0x17B4, c == 0x17B5, c == 0x180E, c == 0x3164, c == 0xFEFF, c == 0xFFA0:
		return true
	case c >= 0x180B && c <= 0x180F, c >= 0x200B && c <= 0x200F, c >= 0x202A && c <= 0x202E,
		c >= 0x2060 && c <= 0x206F, c >= 0xFE00 && c <= 0xFE0F:
		return true
	}
	return false
}

// collapse joins the words of s with single spaces, ignoring invisible
// padding characters.
func collapse(s string) string {
	return strings.Join(strings.Fields(stripInvisible(s)), " ")
}

// parseHTML walks the HTML once, collecting links, images, active content,
// visible text, and the attributes merge tags can hide in. Its cost is
// linear in the size of the HTML.
func parseHTML(s string) *parsedHTML {
	p := &parsedHTML{}
	z := html.NewTokenizer(strings.NewReader(s))
	var open *link
	var linkText, words, text, block, attrs strings.Builder
	var blocks []string
	active := map[string]bool{}
	addActive := func(name string) {
		if !active[name] {
			active[name] = true
			p.Active = append(p.Active, name)
		}
	}
	endBlock := func() {
		b := collapse(block.String())
		block.Reset()
		if b != "" {
			blocks = append(blocks, b)
		}
	}
	addAttr := func(v *string) {
		if v != nil && strings.ContainsAny(*v, "{}|%[") {
			attrs.WriteString(*v)
			attrs.WriteByte('\n')
			if u, err := url.QueryUnescape(*v); err == nil && u != *v {
				attrs.WriteString(u)
				attrs.WriteByte('\n')
			}
		}
	}
	// Text in the head, title, styles, and scripts is not visible. A head
	// whose end tag was left out ends at the body.
	inHead, skip := false, 0
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			endBlock()
			p.Text = collapse(text.String())
			p.Body = bodyText(blocks)
			p.Attrs = attrs.String()
			return p
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if blockTags[t.Data] {
				endBlock()
			}
			switch t.Data {
			case "head":
				if tt == html.StartTagToken {
					inHead = true
				}
			case "body":
				inHead = false
			case "title", "style":
				if tt == html.StartTagToken {
					skip++
				}
			case "a":
				if href := attr(t, "href"); href != nil {
					addAttr(href)
					open = &link{Href: strings.TrimSpace(*href)}
					linkText.Reset()
					words.Reset()
				}
			case "script":
				if tt == html.StartTagToken {
					skip++
				}
				if typ := attr(t, "type"); typ == nil || !strings.EqualFold(strings.TrimSpace(*typ), "application/ld+json") {
					addActive(t.Data)
				}
			case "form", "iframe", "object", "embed":
				addActive(t.Data)
			case "img":
				src := attr(t, "src")
				alt := attr(t, "alt")
				addAttr(src)
				addAttr(alt)
				if src == nil {
					continue
				}
				p.ImagesTotal++
				if open != nil && alt != nil {
					linkText.WriteString(" " + *alt)
				}
				if len(p.Images) >= maxImagesExamined {
					continue
				}
				im := image{Src: strings.TrimSpace(*src), Alt: alt}
				im.Pixel, im.Hidden = imageSize(t)
				p.Images = append(p.Images, im)
			}
		case html.TextToken:
			if inHead || skip > 0 {
				continue
			}
			t := z.Text()
			text.Write(t)
			text.WriteByte(' ')
			block.Write(t)
			block.WriteByte(' ')
			if open != nil {
				linkText.Write(t)
				words.Write(t)
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			n := string(name)
			if blockTags[n] {
				endBlock()
			}
			switch n {
			case "head":
				inHead = false
			case "title", "style", "script":
				if skip > 0 {
					skip--
				}
			case "a":
				if open != nil {
					open.Text = collapse(linkText.String())
					open.Words = collapse(words.String())
					p.LinksTotal++
					if len(p.Links) < maxLinksExamined {
						p.Links = append(p.Links, *open)
					}
					open = nil
				}
			}
		}
	}
}

// imageSize reports whether an image is a tracking pixel (sized 0 or 1 in
// both directions, by attribute or inline CSS) and whether it is hidden.
func imageSize(t html.Token) (pixel, hidden bool) {
	tiny := func(v string) bool {
		v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), "px")
		v = strings.TrimSpace(v)
		return v == "0" || v == "1"
	}
	w, h := false, false
	if v := attr(t, "width"); v != nil {
		w = tiny(*v)
	}
	if v := attr(t, "height"); v != nil {
		h = tiny(*v)
	}
	if st := attr(t, "style"); st != nil {
		for _, decl := range strings.Split(*st, ";") {
			k, v, ok := strings.Cut(decl, ":")
			if !ok {
				continue
			}
			k = strings.ToLower(strings.TrimSpace(k))
			v = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "!important")))
			switch k {
			case "width", "max-width":
				w = w || tiny(v)
			case "height", "max-height":
				h = h || tiny(v)
			case "display":
				hidden = hidden || v == "none"
			case "visibility":
				hidden = hidden || v == "hidden"
			}
		}
	}
	return w && h, hidden
}

func attr(t html.Token, name string) *string {
	for _, a := range t.Attr {
		if a.Key == name {
			v := a.Val
			return &v
		}
	}
	return nil
}

var textURL = regexp.MustCompile(`https?://[^\s<>"')\]]+`)

// trimURL drops sentence punctuation that a plain text URL ran into.
func trimURL(u string) string {
	return strings.TrimRight(u, ".,;:!?*")
}

// Merge tags that survived rendering. Each pattern is one platform's
// syntax. Group is the submatch that is the tag, when the pattern needs
// context around it.
var placeholderPatterns = []struct {
	re    *regexp.Regexp
	group int
}{
	{regexp.MustCompile(`\{\{[^{}\n]{1,80}\}\}`), 0},            // Liquid, Handlebars, Kit
	{regexp.MustCompile(`\{%[^%\n]{1,80}%\}`), 0},               // Liquid tags
	{regexp.MustCompile(`\*\|[A-Z0-9_:]{1,40}\|\*`), 0},         // Mailchimp
	{regexp.MustCompile(`%%[A-Za-z_][A-Za-z0-9_.]{0,40}%%`), 0}, // Salesforce, Buttondown style
	{regexp.MustCompile(`\[[A-Z]+_[A-Z_]+\]`), 0},               // [FIRST_NAME]
	// Ghost: {first_name} or {first_name, "there"}, not inside {{ }}.
	{regexp.MustCompile(`(?:^|[^{])(\{(?:first_name|name|email)(?:,\s*"[^"\n]{0,40}")?\})`), 1},
}

func (r *run) content() {
	if r.msg.HTML != "" {
		r.parsed = parseHTML(r.msg.HTML)
	} else {
		r.parsed = &parsedHTML{}
		for _, u := range textURL.FindAllString(r.msg.Text, -1) {
			r.parsed.LinksTotal++
			if len(r.parsed.Links) < maxLinksExamined {
				r.parsed.Links = append(r.parsed.Links, link{Href: trimURL(u)})
			}
		}
	}

	hosts := map[string]bool{}
	for _, l := range r.parsed.Links {
		if u, err := url.Parse(l.Href); err == nil && u.Host != "" {
			hosts[strings.ToLower(u.Hostname())] = true
		}
	}
	for h := range hosts {
		r.fp.LinkHosts = append(r.fp.LinkHosts, h)
	}
	sort.Strings(r.fp.LinkHosts)
	if len(r.fp.LinkHosts) > maxLinkHosts {
		r.fp.LinkHosts = r.fp.LinkHosts[:maxLinkHosts]
	}
	r.fp.Links = r.parsed.LinksTotal
	r.fp.Images = r.parsed.ImagesTotal

	checks := []struct {
		id, title string
		run       func()
	}{
		{"unsub.visible", "Visible unsubscribe link not checked", r.checkVisibleUnsub},
		{"content.placeholders", "Merge tags not checked", r.checkPlaceholders},
		{"content.insecure_links", "Links not checked for https", r.checkInsecureLinks},
		{"content.image_alt", "Alt text not checked", r.checkImageAlt},
		{"content.subject", "Subject not checked", r.checkSubject},
		{"content.preheader", "Preview text not checked", r.checkPreheader},
		{"content.text_ratio", "Text not checked", r.checkImageOnly},
		{"content.shorteners", "Link shorteners not checked", r.checkShorteners},
		{"content.link_text", "Link text not checked", r.checkLinkTextMismatch},
		{"content.active", "Active content not checked", r.checkActiveContent},
		{"content.blocklists", "Link domains not looked up", r.checkBlocklists},
	}
	for _, c := range checks {
		if r.ctx.Err() != nil {
			cat := verdict.Content
			if strings.HasPrefix(c.id, "unsub.") {
				cat = verdict.Unsub
			}
			r.add(skipped(c.id, cat, c.title, "The check was stopped before it finished."))
			continue
		}
		c.run()
	}
	if r.ctx.Err() != nil {
		r.add(skipped("content.links", verdict.Content, "Links not checked", "The check was stopped before it finished."))
		r.add(skipped("content.images", verdict.Content, "Images not checked", "The check was stopped before it finished."))
		return
	}
	r.checkLinks()
}

// capped puts items in the evidence under key, keeping at most
// maxEvidenceItems and recording the full count under key_total when there
// are more.
func capped[T any](ev map[string]any, key string, items []T) {
	if len(items) > maxEvidenceItems {
		ev[key+"_total"] = len(items)
		items = items[:maxEvidenceItems]
	}
	ev[key] = items
}

// noteLimit records in the evidence that only the first links or images
// were examined.
func (r *run) noteLimit(ev map[string]any) map[string]any {
	if !r.parsed.truncated() {
		return ev
	}
	if ev == nil {
		ev = map[string]any{}
	}
	ev["links_total"], ev["links_examined"] = r.parsed.LinksTotal, len(r.parsed.Links)
	ev["images_total"], ev["images_examined"] = r.parsed.ImagesTotal, len(r.parsed.Images)
	return ev
}

// partial turns a pass into info when the message had more links or images
// than were examined, since the rest were not looked at.
func (r *run) partial(c verdict.Check) verdict.Check {
	if !r.parsed.truncated() {
		return c
	}
	c.Evidence = r.noteLimit(c.Evidence)
	if c.Status == verdict.Pass {
		c.Status = verdict.Info
		c.Title += fmt.Sprintf(" in the first %d links and %d images", len(r.parsed.Links), len(r.parsed.Images))
	}
	return c
}

func (r *run) checkPlaceholders() {
	var found []string
	seen := map[string]bool{}
	total := 0
	for _, body := range []string{r.msg.get("Subject"), r.msg.Text, r.parsed.Text, r.parsed.Attrs} {
		for _, p := range placeholderPatterns {
			for _, m := range p.re.FindAllStringSubmatch(body, -1) {
				tag := m[p.group]
				if seen[tag] {
					continue
				}
				seen[tag] = true
				total++
				if len(found) < maxEvidenceItems {
					found = append(found, tag)
				}
			}
		}
	}
	if len(found) == 0 {
		r.add(verdict.Check{ID: "content.placeholders", Category: verdict.Content, Status: verdict.Pass, Title: "No unrendered merge tags"})
		return
	}
	ev := map[string]any{"found": found}
	if total > len(found) {
		ev["found_total"] = total
	}
	r.add(verdict.Check{
		ID: "content.placeholders", Category: verdict.Content, Status: verdict.Fail,
		Title:    "Unrendered merge tags: " + strings.Join(found, ", "),
		Evidence: ev,
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Check the spelling of these tags and that every subscriber has a value or a default."},
	})
}

// visibleText is the HTML without tags, comments, styles, or scripts, so a
// template's own CSS braces are not mistaken for merge tags.
func visibleText(s string) string {
	if s == "" {
		return ""
	}
	return parseHTML(s).Text
}

func (r *run) checkInsecureLinks() {
	var insecure []string
	for _, l := range r.parsed.Links {
		if strings.HasPrefix(strings.ToLower(l.Href), "http://") && len(insecure) < 20 {
			insecure = append(insecure, l.Href)
		}
	}
	for _, im := range r.parsed.Images {
		if strings.HasPrefix(strings.ToLower(im.Src), "http://") && len(insecure) < 20 {
			insecure = append(insecure, im.Src)
		}
	}
	if len(insecure) == 0 {
		r.add(verdict.Check{ID: "content.insecure_links", Category: verdict.Content, Status: verdict.Pass, Title: "Every link and image uses https"})
		return
	}
	r.add(verdict.Check{
		ID: "content.insecure_links", Category: verdict.Content, Status: verdict.Warn,
		Title:    "Some links or images use http",
		Evidence: map[string]any{"urls": insecure},
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Change these to https. Some clients block http images, and browsers warn on http links."},
	})
}

func (r *run) checkImageAlt() {
	var missing []string
	content := 0
	for _, im := range r.parsed.Images {
		if im.Pixel || im.Hidden {
			continue
		}
		content++
		if im.Alt == nil && len(missing) < 20 {
			missing = append(missing, im.Src)
		}
	}
	switch {
	case content == 0:
		r.add(verdict.Check{ID: "content.image_alt", Category: verdict.Content, Status: verdict.Info, Title: "No content images"})
	case len(missing) == 0:
		r.add(verdict.Check{ID: "content.image_alt", Category: verdict.Content, Status: verdict.Pass, Title: "Every image has alt text"})
	default:
		r.add(verdict.Check{
			ID: "content.image_alt", Category: verdict.Content, Status: verdict.Warn,
			Title:    "Images without alt text",
			Evidence: map[string]any{"images": missing},
			Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Add alt text. Many readers have images off by default, and screen readers need it."},
		})
	}
}
