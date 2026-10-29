package engine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendscore/sendscore/verdict"
)

// linkServer is a link server that records the paths it was asked for. Paths
// starting with /slow wait until the request is cancelled.
type linkServer struct {
	mu    sync.Mutex
	paths []string
}

func (rec *linkServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec.mu.Lock()
	rec.paths = append(rec.paths, r.URL.RequestURI())
	rec.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/slow") {
		<-r.Context().Done()
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (rec *linkServer) got() []string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]string(nil), rec.paths...)
}

func linkPage(links ...string) string {
	var b strings.Builder
	b.WriteString(`<html><body><p>` + strings.Repeat("Real words about photography and light. ", 10) + `</p>`)
	for _, l := range links {
		b.WriteString("<p>" + l + "</p>")
	}
	b.WriteString(`<p><a href="https://example.com/unsubscribe?u=1">Unsubscribe</a></p></body></html>`)
	return b.String()
}

func TestDeadlineLeavesLinksUncheckedNotBroken(t *testing.T) {
	rec := &linkServer{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	var links []string
	for i := range 4 {
		links = append(links, fmt.Sprintf(`<a href="%s/slow/%d">Slow %d</a>`, srv.URL, i, i))
	}
	raw := buildMessage(t, msgOpts{sign: true, html: linkPage(links...)})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	v, err := Analyze(ctx, raw, Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	c := find(t, v, "content.links")
	if c.Status != verdict.Skipped {
		t.Fatalf("content.links = %s %q, want skipped", c.Status, c.Title)
	}
	if !strings.Contains(c.Reason, "4 of 4 links not checked") {
		t.Errorf("reason = %q", c.Reason)
	}
	if c.Evidence["checked"] != 0 {
		t.Errorf("checked = %v, want 0", c.Evidence["checked"])
	}
	if c.Fix != nil {
		t.Errorf("a timeout must not carry a fix: %+v", c.Fix)
	}
}

func TestDeadlineKeepsFinishedResults(t *testing.T) {
	rec := &linkServer{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	html := linkPage(
		`<a href="`+srv.URL+`/fast/1">One</a>`,
		`<a href="`+srv.URL+`/fast/2">Two</a>`,
		`<a href="`+srv.URL+`/slow/1">Three</a>`,
	)
	raw := buildMessage(t, msgOpts{sign: true, html: html})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	v, err := Analyze(ctx, raw, Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	c := find(t, v, "content.links")
	if c.Status != verdict.Skipped || c.Evidence["checked"] != 2 {
		t.Fatalf("content.links = %s %q checked=%v, want skipped with 2 checked", c.Status, c.Reason, c.Evidence["checked"])
	}
	if nc, _ := c.Evidence["not_checked"].([]string); len(nc) != 1 || !strings.HasSuffix(nc[0], "/slow/1") {
		t.Errorf("not_checked = %v", c.Evidence["not_checked"])
	}
}

func TestActionLinksAreNeverFetched(t *testing.T) {
	rec := &linkServer{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	html := linkPage(
		// Non-English text on a URL with no English word.
		`<a href="`+srv.URL+`/action/x?token=1">Abbestellen</a>`,
		`<a href="`+srv.URL+`/action/y?token=2">Se désabonner</a>`,
		// Non-English words in the path.
		`<a href="`+srv.URL+`/desinscription?id=3">ici</a>`,
		`<a href="`+srv.URL+`/nieuwsbrief/uitschrijven/4">hier</a>`,
		`<a href="`+srv.URL+`/newsletter/abmelden">hier</a>`,
		// Same endpoint as List-Unsubscribe with another token.
		`<a href="`+srv.URL+`/lu/zz/other-token">click here</a>`,
		// The same tracked URL twice, neutral text first.
		`<a href="`+srv.URL+`/c/abc123">here</a>`,
		`<a href="`+srv.URL+`/c/abc123">Unsubscribe</a>`,
		`<a href="`+srv.URL+`/posts/fine">A post</a>`,
	)
	headers := "List-Unsubscribe: <" + srv.URL + "/lu/zz/tok-1>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html, headers: headers}), Options{CheckLinks: true, HTTPClient: srv.Client()})
	for _, p := range rec.got() {
		if p != "/posts/fine" {
			t.Errorf("fetched action link %s", p)
		}
	}
	c := find(t, v, "content.links")
	if c.Status != verdict.Pass {
		t.Errorf("content.links = %s %q", c.Status, c.Title)
	}
	if nf, _ := c.Evidence["not_followed"].([]string); len(nf) != 8 {
		t.Errorf("not_followed = %v, want 8", c.Evidence["not_followed"])
	}
}

func TestIsActionLinkOtherLanguages(t *testing.T) {
	for _, u := range []string{
		"https://pub.substack.com/action/disable_email?token=abc",
		"https://x.example/fr/d%C3%A9sabonnement?id=1",
		"https://x.example/es/darse-de-baja",
		"https://x.example/it/cancellazione",
		"https://x.example/dk/afmeld?x=1",
		"https://x.example/r?go=desinscribirse",
	} {
		if !isActionLink(u, nil) {
			t.Errorf("%s is not an action link", u)
		}
	}
	if isActionLink("https://abmeld.example/posts/1", nil) {
		t.Error("a word in the host name alone must not make an action link")
	}
	if isActionLink("https://x.example/posts/1", []string{"https://x.example/unsub?u=1"}) {
		t.Error("the root directory of a List-Unsubscribe URI must not cover the whole site")
	}
}

func TestSafeHTTPClientIdleTimeout(t *testing.T) {
	tr, ok := SafeHTTPClient().Transport.(*http.Transport)
	if !ok || tr.IdleConnTimeout <= 0 {
		t.Fatalf("SafeHTTPClient transport has no idle timeout")
	}
}

func mimeMessage(body string) []byte {
	return []byte("From: Daily Tips <tips@example.com>\r\nTo: a@b.example\r\nSubject: Hi\r\n" +
		"Date: Tue, 28 Oct 2026 13:12:04 +0000\r\nMessage-ID: <x@example.com>\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"b1\"\r\n\r\n" + body)
}

func TestBadPartDoesNotHideLaterParts(t *testing.T) {
	m, err := parseMessage(mimeMessage(
		"--b1\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8gd29ybGQ\r\n" +
			"--b1\r\nContent-Type: text/html\r\n\r\n<p>Hi</p><a href=\"https://example.com/unsubscribe\">Unsubscribe</a>\r\n--b1--\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.MIMEErr == nil || !strings.Contains(m.MIMEErr.Error(), "decoding text/plain") {
		t.Errorf("MIMEErr = %v", m.MIMEErr)
	}
	if !strings.Contains(m.HTML, "Unsubscribe") {
		t.Errorf("HTML part after the bad part was not read: %q", m.HTML)
	}
	if !strings.HasPrefix(m.Text, "hello wor") {
		t.Errorf("Text = %q, want what decoded", m.Text)
	}
}

func TestInvalidMediaParameterIsTolerated(t *testing.T) {
	for _, ct := range []string{
		"text/html; charset=utf-8; name=",
		"text/html; charset=utf-8; name=file name.html",
		"text/html; charset=utf-8 (comment)",
		"text/html;;",
	} {
		m, err := parseMessage(mimeMessage("--b1\r\nContent-Type: " + ct + "\r\n\r\n<p>Hi</p>\r\n--b1--\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		if m.MIMEErr != nil || !strings.Contains(m.HTML, "Hi") || len(m.MIMENotes) != 1 {
			t.Errorf("%q: err=%v html=%q notes=%v", ct, m.MIMEErr, m.HTML, m.MIMENotes)
		}
	}
	m, _ := parseMessage(mimeMessage("--b1\r\nContent-Type: text/plain; charset=windows-1252; name=\r\n\r\ncaf\xe9\r\n--b1--\r\n"))
	if !strings.HasPrefix(m.Text, "café") {
		t.Errorf("charset of a part with a bad parameter was lost: %q", m.Text)
	}
}

func TestManyPartsAreTruncatedNotMalformed(t *testing.T) {
	var b strings.Builder
	b.WriteString("--b1\r\nContent-Type: text/html\r\n\r\n<p>Hi</p>\r\n")
	for i := range 70 {
		fmt.Fprintf(&b, "--b1\r\nContent-Type: image/png\r\nContent-ID: <i%d>\r\n\r\nxx\r\n", i)
	}
	b.WriteString("--b1--\r\n")
	m, err := parseMessage(mimeMessage(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if m.MIMEErr != nil || len(m.MIMENotes) != 1 || !strings.Contains(m.HTML, "Hi") {
		t.Errorf("err=%v notes=%v", m.MIMEErr, m.MIMENotes)
	}
}

func TestAddrDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Name <a@Example.com>":                       "example.com",
		"<a@example.com>":                            "example.com",
		"a@example.com, b@evil.test":                 "example.com",
		"A <a@example.com>, B <b@x.test>":            "example.com",
		"=?windows-1252?Q?Caf=E9?= <a@cafe.example>": "cafe.example",
		"not an address, b@evil.test":                "",
		"<>":                                         "",
		"bounce@bounce.example.com":                  "bounce.example.com",
	} {
		if got := addrDomain(in); got != want {
			t.Errorf("addrDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCodeSamplesAreNotMergeTags(t *testing.T) {
	for _, body := range []string{
		`<p>Try this.</p><pre><code>print(f"Hello {name}")</code></pre>`,
		`<p>Try <code>{{ .Title }}</code> and <code>{% for x in items %}</code>.</p>`,
		"<p>In JavaScript, write `Hello ${name}` with backticks.</p>",
		`<p>In Python, write print(f"Hello {name}") to greet.</p>`,
	} {
		html := strings.Replace(goodHTML, "<p>Hello. Today: shooting into the sun.</p>", body, 1)
		v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html, text: "Hello. " + visibleText(body) + "\r\nUnsubscribe: https://example.com/unsubscribe?u=1\r\n"}), Options{})
		if c := find(t, v, "content.placeholders"); c.Status != verdict.Pass {
			t.Errorf("%s: %s %q", body, c.Status, c.Title)
		}
	}
	html := strings.Replace(goodHTML, "Hello.", "Hello {first_name}.", 1)
	wantStatus(t, analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{}), "content.placeholders", verdict.Fail)
}

func TestBlocklistLooksUpFullHost(t *testing.T) {
	dns := goodDNS()
	dns.ip["evil.weebly.com.dbl.spamhaus.org"] = []net.IPAddr{{IP: net.ParseIP("127.0.1.2")}}
	html := strings.Replace(goodHTML, "https://example.com/posts/sun", "https://evil.weebly.com/login", 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{Resolver: dns, Blocklists: publicLists})
	c := find(t, v, "content.blocklists")
	if c.Status != verdict.Fail || !strings.Contains(c.Title, "evil.weebly.com") {
		t.Errorf("content.blocklists = %s %q", c.Status, c.Title)
	}
	v = analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Blocklists: publicLists})
	if c := find(t, v, "content.blocklists"); c.Status != verdict.Pass || !strings.HasPrefix(c.Title, "No link host or domain is on") {
		t.Errorf("content.blocklists = %s %q", c.Status, c.Title)
	}
}

func TestOverLimitChecksAreInfo(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<p>` + strings.Repeat("Real words about photography and light. ", 10) + `</p>`)
	for i := range maxLinksExamined {
		fmt.Fprintf(&b, `<a href="https://example.com/p/%d">Post</a><img src="https://cdn.example.com/%d.jpg" alt="x">`, i, i)
	}
	b.WriteString(`<a href="http://example.com/late">Late</a><img src="http://cdn.example.com/late.jpg">`)
	b.WriteString(`<p><a href="https://example.com/unsubscribe?u=1">Unsubscribe</a></p>`)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: b.String()}), Options{})
	for _, id := range []string{"content.insecure_links", "content.image_alt"} {
		c := find(t, v, id)
		if c.Status != verdict.Info || c.Evidence["links_total"] != maxLinksExamined+2 {
			t.Errorf("%s = %s %q %v, want info with totals", id, c.Status, c.Title, c.Evidence)
		}
	}
}

func TestEvidenceListsCarryTotals(t *testing.T) {
	var b strings.Builder
	for i := range 30 {
		fmt.Fprintf(&b, `<a href="http://example.com/p/%d">Post</a><img src="https://cdn.example.com/%d.jpg">`, i, i)
	}
	html := strings.Replace(goodHTML, "<p>Hello. Today: shooting into the sun.</p>", "<p>"+b.String()+"</p>", 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	c := find(t, v, "content.insecure_links")
	if urls, _ := c.Evidence["urls"].([]string); len(urls) != maxEvidenceItems || c.Evidence["urls_total"] != 30 {
		t.Errorf("insecure_links evidence = %v", c.Evidence)
	}
	c = find(t, v, "content.image_alt")
	if imgs, _ := c.Evidence["images"].([]string); len(imgs) != maxEvidenceItems || c.Evidence["images_total"] != 30 {
		t.Errorf("image_alt evidence = %v", c.Evidence)
	}
}

func TestMIMENotesWarn(t *testing.T) {
	raw := buildMessage(t, msgOpts{})
	raw = bytes.Replace(raw, []byte("Content-Type: text/plain; charset=utf-8"), []byte(`Content-Type: text/plain; charset=utf-8; bad=`), 1)
	v := analyze(t, raw, Options{Resolver: OfflineResolver{}})
	c := find(t, v, "struct.mime")
	if c.Status == verdict.Pass {
		t.Fatalf("struct.mime = pass with a malformed Content-Type parameter")
	}
	if c.Status == verdict.Warn && c.Evidence["notes"] == nil {
		t.Errorf("struct.mime warn without notes: %+v", c)
	}
}
