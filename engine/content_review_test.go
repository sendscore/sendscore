package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/idna"

	"github.com/sendscore/sendscore/verdict"
)

// within fails the test when f takes longer than d.
func within(t *testing.T, d time.Duration, f func()) {
	t.Helper()
	start := time.Now()
	f()
	if took := time.Since(start); took > d {
		t.Errorf("took %s, want under %s", took, d)
	}
}

func TestFoldedHeadersAreLinear(t *testing.T) {
	// 200k continuation lines fit under the header limit and must parse in
	// linear time.
	var b strings.Builder
	b.WriteString("X-Fold: start\r\n")
	for i := 0; i < 200_000; i++ {
		b.WriteString(" a\r\n")
	}
	raw := append([]byte(b.String()), buildMessage(t, msgOpts{})...)
	within(t, 2*time.Second, func() {
		if _, err := Analyze(context.Background(), raw, Options{Resolver: OfflineResolver{}}); err != nil {
			t.Fatal(err)
		}
	})

	// 300k lines are past the limit and are refused at once.
	b.Reset()
	b.WriteString("X-Fold: start\r\n")
	for i := 0; i < 300_000; i++ {
		b.WriteString(" a\r\n")
	}
	raw = append([]byte(b.String()), buildMessage(t, msgOpts{})...)
	within(t, time.Second, func() {
		if _, err := Analyze(context.Background(), raw, Options{Resolver: OfflineResolver{}}); err == nil {
			t.Error("a header block over the limit was accepted")
		}
	})
}

func TestTooManyHeadersAreRefused(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxHeaders+1; i++ {
		fmt.Fprintf(&b, "X-H%d: v\r\n", i)
	}
	raw := append([]byte(b.String()), buildMessage(t, msgOpts{})...)
	if _, err := Analyze(context.Background(), raw, Options{Resolver: OfflineResolver{}}); err == nil {
		t.Error("a message with too many headers was accepted")
	}
}

func TestFoldedHeaderValue(t *testing.T) {
	h, err := rawHeaders([]byte("Subject: one\r\n two\r\n\tthree\r\nTo: a@b.c\r\n\r\nbody"))
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 || h[0].Value != "one two three" || h[1].Value != "a@b.c" {
		t.Errorf("headers = %+v", h)
	}
}

func TestManyUniqueLinksAreCapped(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100_000; i++ {
		fmt.Fprintf(&b, `<a href="https://bit.ly/%d">x</a><a href="https://site%d.test/">y</a>`, i, i)
	}
	html := strings.Replace(goodHTML, "</body>", b.String()+"</body>", 1)
	raw := buildMessage(t, msgOpts{sign: true, html: html})
	var v *verdict.Verdict
	within(t, 3*time.Second, func() {
		v = analyze(t, raw, Options{Blocklists: publicLists})
	})
	c := find(t, v, "content.shorteners")
	if c.Status != verdict.Warn || len(c.Evidence["links"].([]string)) != maxEvidenceItems || c.Evidence["links_total"] == nil {
		t.Errorf("shorteners = %s %v", c.Status, c.Evidence["links_total"])
	}
	if c.Evidence["links_examined"] != maxLinksExamined {
		t.Errorf("links_examined = %v", c.Evidence["links_examined"])
	}
	if got := v.Fingerprint.Links; got != 200_002 {
		t.Errorf("fingerprint links = %d", got)
	}
	if len(v.Fingerprint.LinkHosts) > maxLinkHosts {
		t.Errorf("fingerprint has %d link hosts", len(v.Fingerprint.LinkHosts))
	}
	wantStatus(t, v, "content.blocklists", verdict.Skipped)
	// Nothing passes on a partial look.
	if c := find(t, v, "content.link_text"); c.Status == verdict.Pass {
		t.Errorf("link_text passed after examining only part of the links")
	}
	out, _ := json.Marshal(v)
	if len(out) > 64<<10 {
		t.Errorf("verdict JSON is %d bytes", len(out))
	}
}

// recorder is a transport that records each request and answers 200.
type recorder struct {
	mu   sync.Mutex
	seen []string
}

func (rt *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.seen = append(rt.seen, req.Method+" "+req.URL.String())
	rt.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: http.NoBody, Request: req}, nil
}

func TestUnsubscribeTextLinkIsNotFetched(t *testing.T) {
	html := `<html><body><p>Hello there, a short issue for this test.</p>
<p><a href="https://email.mg.example.com/c/eJx1kE1">Read more</a></p>
<p><a href="https://email.mg.example.com/u/eJx9kM2">Unsubscribe</a></p>
<p><a href="https://email.mg.example.com/p/eJx9kM3">Update your preferences</a></p></body></html>`
	rt := &recorder{}
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{CheckLinks: true, HTTPClient: &http.Client{Transport: rt}})
	for _, s := range rt.seen {
		if strings.Contains(s, "/u/") || strings.Contains(s, "/p/") {
			t.Errorf("fetched %s", s)
		}
	}
	c := find(t, v, "content.links")
	nf, _ := c.Evidence["not_followed"].([]string)
	if len(nf) != 2 {
		t.Errorf("not_followed = %v", c.Evidence["not_followed"])
	}
}

func TestRedirectIntoUnsubscribeIsNotFollowed(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/c/abc":
			http.Redirect(w, r, "/unsubscribe?u=42", http.StatusFound)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()
	html := `<html><body><p>Hello there, a short issue for this test.</p><p><a href="` + srv.URL + `/c/abc">Read more</a></p></body></html>`
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{CheckLinks: true, HTTPClient: srv.Client()})
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "HEAD /c/abc" {
		t.Errorf("server saw %v", seen)
	}
	c := find(t, v, "content.links")
	if c.Evidence["redirect_not_followed"] == nil {
		t.Errorf("links evidence = %v", c.Evidence)
	}
}

func TestSafeClientStopsAtActionRedirect(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/unsubscribe?u=1", nil)
	if err := SafeHTTPClient().CheckRedirect(req, []*http.Request{req}); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect = %v", err)
	}
}

func TestPublicIPRefusesSpecialRanges(t *testing.T) {
	for _, ip := range []string{
		"100.64.0.1", "100.100.100.200", "198.18.0.1", "192.0.0.170", "255.255.255.255",
		"0.0.0.0", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "2002:7f00:1::", "::ffff:10.0.0.1",
		"::ffff:127.0.0.1", "fe80::1", "fd00::1", "2001:db8::1",
	} {
		if publicIP(net.ParseIP(ip)) {
			t.Errorf("%s counted as public", ip)
		}
	}
	for _, ip := range []string{"93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c", "64:ff9b::5db8:d70e"} {
		if !publicIP(net.ParseIP(ip)) {
			t.Errorf("%s was refused", ip)
		}
	}
}

func TestBlocklistsLookUpIDNAsASCII(t *testing.T) {
	html := strings.Replace(goodHTML, "</body>", `<p><a href="https://pаypal.com/login">Sign in</a></p></body>`, 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{Blocklists: publicLists})
	c := find(t, v, "content.blocklists")
	want, _ := idna.Lookup.ToASCII("pаypal.com")
	if !strings.Contains(fmt.Sprint(c.Evidence["domains"]), want) {
		t.Errorf("domains = %v, want %s", c.Evidence["domains"], want)
	}
}

func TestBlocklistsInvalidHostIsNotChecked(t *testing.T) {
	long := strings.Repeat("a", 64) + ".test"
	html := strings.Replace(goodHTML, "</body>", `<p><a href="https://`+long+`/x">Sign in</a></p></body>`, 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{Blocklists: publicLists})
	c := find(t, v, "content.blocklists")
	if c.Status != verdict.Skipped || c.Evidence["not_valid"] == nil {
		t.Errorf("blocklists = %s %q %v", c.Status, c.Reason, c.Evidence)
	}
}

const mailchimpFooter = `<table><tr><td>
<em>Copyright (C) 2026 Daily Tips, All rights reserved.</em><br>
You are receiving this email because you opted in via our website.<br><br>
<strong>Our mailing address is</strong><br>Daily Tips, 1 Main Street, Springfield, IL 62701, USA<br><br>
Want to change how you receive these emails?<br>
You can <a href="https://example.us1.list-manage.com/profile?u=1">update your preferences</a> or <a href="https://example.us1.list-manage.com/unsubscribe?u=1">unsubscribe from this list</a>.
</td></tr></table>`

func TestImageOnlyWithBulkFooter(t *testing.T) {
	html := `<html><body><a href="https://example.com/sale"><img src="https://cdn.example.com/flyer.jpg" alt="" width="600"></a>` + mailchimpFooter + `</body></html>`
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.text_ratio", verdict.Warn)

	// The same footer under real copy is an ordinary issue.
	html = `<html><body><img src="https://cdn.example.com/sun.jpg" alt="Sunset"><p>Shoot into the sun with the sun just outside the frame, and meter for the highlights.</p>` + mailchimpFooter + `</body></html>`
	v = analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.text_ratio", verdict.Pass)
}

func TestPreheaderPaddingIsNotText(t *testing.T) {
	pad := strings.Repeat("&#847;&zwnj;&nbsp;", 100)
	html := `<html><body><div style="display:none">` + pad + `</div><p><a href="https://example.com/web">View in browser</a></p><img src="https://cdn.example.com/a.jpg" alt=""></body></html>`
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.preheader", verdict.Warn)
	wantStatus(t, v, "content.text_ratio", verdict.Warn)
	if c := find(t, v, "content.text_ratio"); c.Evidence["text_characters"] != 0 {
		t.Errorf("text_characters = %v", c.Evidence["text_characters"])
	}
}

func TestUnclosedHead(t *testing.T) {
	html := `<html><head><meta charset=utf-8><style>p{color:red}</style><body><img alt=x src="https://cdn.example.com/a.jpg"><p>Shooting straight into the sun flattens contrast and blows out the sky, but a small change in angle fixes most of it, so try it this week.</p><p>Hi {{ first_name }}</p></body></html>`
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.preheader", verdict.Pass)
	wantStatus(t, v, "content.text_ratio", verdict.Pass)
	wantStatus(t, v, "content.placeholders", verdict.Fail)
}

func TestPixelsSizedWithUnitsOrCSS(t *testing.T) {
	for _, px := range []string{
		`<img src="https://open.example.com/o/a" style="width:1px;height:1px">`,
		`<img src="https://open.example.com/o/b" width="1px" height="1px">`,
		`<img src="https://open.example.com/o/c" style="Display:None">`,
	} {
		html := `<html><body><img src="https://cdn.example.com/sun.jpg" alt="Sunset"><p>A caption long enough to count as real copy for one image.</p>` + px + `</body></html>`
		v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
		wantStatus(t, v, "content.image_alt", verdict.Pass)
		wantStatus(t, v, "content.text_ratio", verdict.Pass)
	}
}

func TestPlainTextURLsDropTrailingPunctuation(t *testing.T) {
	raw := []byte("From: Tips <tips@example.com>\r\nTo: a@b.test\r\nSubject: New post\r\nDate: Tue, 28 Oct 2026 13:12:04 +0000\r\nMessage-ID: <x@example.com>\r\n\r\n" +
		"New post is up: https://example.com/post. Also https://example.com/a, and https://x.com/b!\r\n")
	rt := &recorder{}
	analyze(t, raw, Options{Resolver: OfflineResolver{}, CheckLinks: true, HTTPClient: &http.Client{Transport: rt}})
	got := strings.Join(rt.seen, " ")
	for _, want := range []string{"HEAD https://example.com/post ", "HEAD https://example.com/a", "HEAD https://x.com/b"} {
		if !strings.Contains(got+" ", want) {
			t.Errorf("requests %v, want %s", rt.seen, want)
		}
	}
	if strings.Contains(got, "post.") || strings.Contains(got, "/a,") || strings.Contains(got, "/b!") {
		t.Errorf("requests kept punctuation: %v", rt.seen)
	}
}

func TestLinkTextBrandedTrackingSubdomain(t *testing.T) {
	html := `<html><body><p>A short note this week, with one link to the new site.</p>
<p><a href="https://email.mg.example.com/c/abc">sendscore.ai</a></p>
<p><a href="https://email.mg.example.com/u/def">Unsubscribe</a></p></body></html>`
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.link_text", verdict.Pass)

	// A link to a domain that is not the sender's is still flagged.
	html = strings.Replace(html, "email.mg.example.com/c/abc", "email.mg.example.net/c/abc", 1)
	v = analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.link_text", verdict.Warn)
}

func TestVisibleUnsubPrefersHTML(t *testing.T) {
	html := `<html><body><p>Hello there, a short issue with no footer link at all.</p></body></html>`
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html, text: "Hello.\r\nTo unsubscribe reply STOP.\r\n"}), Options{})
	wantStatus(t, v, "unsub.visible", verdict.Warn)
}

func TestPlaceholdersInAttributesAndGhost(t *testing.T) {
	html := strings.Replace(goodHTML, "</body>", `<p><a href="https://example.com/?e={{ subscriber.email }}">Read</a> <a href="https://example.com/?f=%7B%7Bfirst%7D%7D">Two</a> <img src="https://cdn.example.com/x.jpg" alt="*|FNAME|*"></p><p>Hi {first_name, "there"},</p></body>`, 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	c := find(t, v, "content.placeholders")
	found := fmt.Sprint(c.Evidence["found"])
	for _, want := range []string{"{{ subscriber.email }}", "{{first}}", "*|FNAME|*", `{first_name, "there"}`} {
		if !strings.Contains(found, want) {
			t.Errorf("found = %s, want %s", found, want)
		}
	}
}

func TestGhostTagsIgnoreCodeAndCSS(t *testing.T) {
	html := `<html><head><style>.a{color:red} .name{display:block}</style></head><body><p>Config looks like {"name": "x"} and function f() {return}.</p><p>Hello {{first_name}}.</p></body></html>`
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	c := find(t, v, "content.placeholders")
	if found := c.Evidence["found"].([]string); len(found) != 1 || found[0] != "{{first_name}}" {
		t.Errorf("found = %v", found)
	}
}

func TestCancelledContextSkipsContentChecks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v, err := Analyze(ctx, buildMessage(t, msgOpts{sign: true}), Options{Resolver: OfflineResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"content.placeholders", "content.text_ratio", "content.links"} {
		wantStatus(t, v, id, verdict.Skipped)
	}
}

func TestLinkCheckOffReasonIsNeutral(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{})
	if c := find(t, v, "content.links"); c.Reason != "Link checking is off." {
		t.Errorf("reason = %q", c.Reason)
	}
}
