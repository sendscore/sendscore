package engine

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"

	"github.com/sendscore/sendscore/verdict"
)

type link struct {
	Href string
	Text string
}

type image struct {
	Src    string
	Alt    *string
	Pixel  bool
	Hidden bool
}

type parsedHTML struct {
	Links  []link
	Images []image
}

func parseHTML(s string) *parsedHTML {
	p := &parsedHTML{}
	z := html.NewTokenizer(strings.NewReader(s))
	var open *link
	var text strings.Builder
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return p
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			switch t.Data {
			case "a":
				if href := attr(t, "href"); href != nil {
					open = &link{Href: strings.TrimSpace(*href)}
					text.Reset()
				}
			case "img":
				src := attr(t, "src")
				if src == nil {
					continue
				}
				w, h := attr(t, "width"), attr(t, "height")
				im := image{Src: strings.TrimSpace(*src), Alt: attr(t, "alt")}
				im.Pixel = w != nil && h != nil && (*w == "1" || *w == "0") && (*h == "1" || *h == "0")
				if st := attr(t, "style"); st != nil && strings.Contains(strings.ReplaceAll(*st, " ", ""), "display:none") {
					im.Hidden = true
				}
				p.Images = append(p.Images, im)
				if open != nil && im.Alt != nil {
					text.WriteString(" " + *im.Alt)
				}
			}
		case html.TextToken:
			if open != nil {
				text.Write(z.Text())
			}
		case html.EndTagToken:
			if open != nil {
				if name, _ := z.TagName(); string(name) == "a" {
					open.Text = strings.Join(strings.Fields(text.String()), " ")
					p.Links = append(p.Links, *open)
					open = nil
				}
			}
		}
	}
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

// Merge tags that survived rendering. Each pattern is one platform's syntax.
var placeholderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\{\{[^{}\n]{1,80}\}\}`),            // Liquid, Handlebars, Kit
	regexp.MustCompile(`\{%[^%\n]{1,80}%\}`),               // Liquid tags
	regexp.MustCompile(`\*\|[A-Z0-9_:]{1,40}\|\*`),         // Mailchimp
	regexp.MustCompile(`%%[A-Za-z_][A-Za-z0-9_.]{0,40}%%`), // Salesforce, Buttondown style
	regexp.MustCompile(`\[[A-Z]+_[A-Z_]+\]`),               // [FIRST_NAME]
}

func (r *run) content() {
	if r.msg.HTML != "" {
		r.parsed = parseHTML(r.msg.HTML)
	} else {
		r.parsed = &parsedHTML{}
		for _, u := range textURL.FindAllString(r.msg.Text, -1) {
			r.parsed.Links = append(r.parsed.Links, link{Href: u})
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
	r.fp.Links = len(r.parsed.Links)
	r.fp.Images = len(r.parsed.Images)

	r.checkVisibleUnsub()
	r.checkPlaceholders()
	r.checkInsecureLinks()
	r.checkImageAlt()
	r.checkLinks()
}

func (r *run) checkPlaceholders() {
	var found []string
	seen := map[string]bool{}
	for _, body := range []string{r.msg.get("Subject"), r.msg.Text, visibleText(r.msg.HTML)} {
		for _, re := range placeholderPatterns {
			for _, m := range re.FindAllString(body, -1) {
				if !seen[m] && len(found) < 20 {
					seen[m] = true
					found = append(found, m)
				}
			}
		}
	}
	if len(found) == 0 {
		r.add(verdict.Check{ID: "content.placeholders", Category: verdict.Content, Status: verdict.Pass, Title: "No unrendered merge tags"})
		return
	}
	r.add(verdict.Check{
		ID: "content.placeholders", Category: verdict.Content, Status: verdict.Fail,
		Title:    "Unrendered merge tags: " + strings.Join(found, ", "),
		Evidence: map[string]any{"found": found},
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Check the spelling of these tags and that every subscriber has a value or a default."},
	})
}

// visibleText is the HTML without tags, comments, styles, or scripts, so a
// template's own CSS braces are not mistaken for merge tags.
func visibleText(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	z := html.NewTokenizer(strings.NewReader(s))
	skip := 0
	for {
		switch z.Next() {
		case html.ErrorToken:
			return b.String()
		case html.StartTagToken:
			if n, _ := z.TagName(); string(n) == "style" || string(n) == "script" {
				skip++
			}
		case html.EndTagToken:
			if n, _ := z.TagName(); (string(n) == "style" || string(n) == "script") && skip > 0 {
				skip--
			}
		case html.TextToken:
			if skip == 0 {
				b.Write(z.Text())
				b.WriteByte(' ')
			}
		}
	}
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
