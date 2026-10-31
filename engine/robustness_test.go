package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendscore/sendscore/verdict"
)

// plainHeaders are complete headers for a hand-built message.
const plainHeaders = "Return-Path: <b@bounce.example.com>\r\nFrom: T <t@example.com>\r\nTo: x@example.net\r\n" +
	"Subject: Hi there\r\nDate: Tue, 28 Oct 2026 13:12:04 +0000\r\nMessage-ID: <a@example.com>\r\n" +
	"List-Unsubscribe: <https://example.com/unsub/x>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"

func checkOf(t *testing.T, v *verdict.Verdict, id string) verdict.Check {
	t.Helper()
	for _, c := range v.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %s", id)
	return verdict.Check{}
}

func htmlMessage(html string) []byte {
	return []byte(plainHeaders + "Content-Type: text/html; charset=utf-8\r\n\r\n" + html + "\r\n")
}

// recordingClient answers 200 to everything and remembers what it was asked.
type recordingClient struct {
	mu   sync.Mutex
	urls []string
	do   func(*http.Request) (*http.Response, error)
}

func (c *recordingClient) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.urls = append(c.urls, req.URL.String())
	c.mu.Unlock()
	if c.do != nil {
		return c.do(req)
	}
	return status(200), nil
}

func (c *recordingClient) asked(s string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, u := range c.urls {
		if strings.Contains(u, s) {
			return true
		}
	}
	return false
}

func status(code int) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}
}

func TestPlaceholderScanIsBounded(t *testing.T) {
	var tags strings.Builder
	for i := range 150000 {
		fmt.Fprintf(&tags, "{{a%d}} ", i)
	}
	cases := map[string][]byte{
		"html":  htmlMessage("<p>" + tags.String() + "</p>"),
		"plain": []byte(plainHeaders + "Content-Type: text/plain\r\n\r\n" + tags.String() + "\r\n"),
		"code": []byte(plainHeaders + "Content-Type: multipart/alternative; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\n\r\n" + tags.String() + "\r\n" +
			"--b\r\nContent-Type: text/html\r\n\r\n<code>" + strings.Repeat("x ", 2<<20) + "</code>\r\n--b--\r\n"),
	}
	for name, raw := range cases {
		start := time.Now()
		v := analyze(t, raw, Options{Resolver: OfflineResolver{}})
		if d := time.Since(start); d > 5*raceFactor*time.Second {
			t.Errorf("%s took %v", name, d)
		}
		if c := checkOf(t, v, "content.placeholders"); c.Status != verdict.Fail {
			t.Errorf("%s: placeholders = %s", name, c.Status)
		}
	}
}

func TestPlaceholdersRespectCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &run{ctx: ctx, msg: &message{Text: "{{a}}"}, parsed: &parsedHTML{}}
	r.checkPlaceholders()
	if len(r.checks) != 1 || r.checks[0].Status != verdict.Skipped {
		t.Errorf("checks = %+v", r.checks)
	}
}

func TestListUnsubscribeIsBounded(t *testing.T) {
	var links strings.Builder
	for i := range 2000 {
		fmt.Fprintf(&links, `<a href="https://l.example/p%d">x</a> `, i)
	}
	raw := []byte(strings.Replace(string(htmlMessage(links.String())), "List-Unsubscribe: <https://example.com/unsub/x>",
		"List-Unsubscribe: "+strings.Repeat("<http://a/b>,", 80000), 1))
	start := time.Now()
	v := analyze(t, raw, Options{Resolver: OfflineResolver{}, CheckLinks: true, HTTPClient: &http.Client{Transport: &recordingClient{}}})
	if d := time.Since(start); d > 5*raceFactor*time.Second {
		t.Errorf("took %v", d)
	}
	if c := checkOf(t, v, "unsub.header"); c.Status == verdict.Pass {
		t.Errorf("unsub.header = %s", c.Status)
	}
}

func TestUnreadBodyIsNotPassed(t *testing.T) {
	bad := `<a href="http://bit.ly/x">{{first_name}}</a><script>1</script>`
	nest := func(depth int) string {
		s := "Content-Type: text/html\r\n\r\n" + bad + "\r\n"
		for i := range depth {
			b := fmt.Sprintf("b%d", i)
			s = "Content-Type: multipart/mixed; boundary=" + b + "\r\n\r\n--" + b + "\r\n" + s + "--" + b + "--\r\n"
		}
		return s
	}
	v := analyze(t, []byte(plainHeaders+nest(10)), Options{Resolver: OfflineResolver{}})
	if c := checkOf(t, v, "struct.mime"); c.Status != verdict.Fail {
		t.Fatalf("struct.mime = %s", c.Status)
	}
	for _, id := range []string{"content.placeholders", "content.shorteners", "content.link_text", "content.active", "content.insecure_links", "unsub.visible"} {
		if c := checkOf(t, v, id); c.Status != verdict.Skipped {
			t.Errorf("%s = %s, want skipped", id, c.Status)
		}
	}
	if c := checkOf(t, v, "content.subject"); c.Status == verdict.Skipped {
		t.Errorf("content.subject reads no body, but was skipped")
	}
}

func TestBrokenPartBesideTheHTMLStillChecks(t *testing.T) {
	raw := []byte(plainHeaders + "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/html\r\n\r\n<p>{{first_name}}</p>\r\n" +
		"--b\r\nContent-Type: /bad\r\n\r\nx\r\n--b--\r\n")
	v := analyze(t, raw, Options{Resolver: OfflineResolver{}})
	if c := checkOf(t, v, "content.placeholders"); c.Status != verdict.Fail {
		t.Errorf("placeholders = %s", c.Status)
	}
}

func TestDuplicateContentTypeParameterIsRead(t *testing.T) {
	raw := []byte(plainHeaders + "Content-Type: text/html; charset=utf-8; charset=latin1\r\n\r\n<p>{{first_name}}</p>\r\n")
	v := analyze(t, raw, Options{Resolver: OfflineResolver{}})
	if c := checkOf(t, v, "content.placeholders"); c.Status != verdict.Fail {
		t.Errorf("placeholders = %s", c.Status)
	}
	if c := checkOf(t, v, "struct.mime"); c.Status != verdict.Warn {
		t.Errorf("struct.mime = %s", c.Status)
	}
}

func TestManyTopLevelHeadersDoNotHideTheBody(t *testing.T) {
	var h strings.Builder
	for i := range 150 {
		fmt.Fprintf(&h, "X-H%d: 1\r\n", i)
	}
	raw := []byte(plainHeaders + h.String() + "Content-Type: text/html\r\n\r\n<p>{{first_name}}</p>\r\n")
	v := analyze(t, raw, Options{Resolver: OfflineResolver{}})
	if c := checkOf(t, v, "content.placeholders"); c.Status != verdict.Fail {
		t.Errorf("placeholders = %s", c.Status)
	}
}

func TestOversizedPartIsNoted(t *testing.T) {
	raw := []byte(plainHeaders + "Content-Type: text/html\r\n\r\n" + strings.Repeat("a", maxDecoded+10))
	v := analyze(t, raw, Options{Resolver: OfflineResolver{}})
	if c := checkOf(t, v, "struct.mime"); c.Status != verdict.Warn {
		t.Errorf("struct.mime = %s", c.Status)
	}
	if c := checkOf(t, v, "content.placeholders"); c.Status != verdict.Skipped {
		t.Errorf("placeholders = %s", c.Status)
	}
}

func TestUnclosedAnchorsAreRecorded(t *testing.T) {
	p := parseHTML(`<a href="http://bit.ly/x">one<a href="http://bit.ly/y">two`)
	if len(p.Links) != 2 || p.Links[0].Text != "one" || p.Links[1].Text != "two" {
		t.Errorf("links = %+v", p.Links)
	}
}

func TestInternationalFromDomain(t *testing.T) {
	if got := addrDomain("a@bücher.example"); got != "xn--bcher-kva.example" {
		t.Errorf("addrDomain = %q", got)
	}
}

func TestUnsubscribeURLMustBeUsable(t *testing.T) {
	for _, u := range []string{"https:", "https://", "https://{{unsub_host}}/x", "https://e.example/u/*|UNSUB|*"} {
		h := "List-Unsubscribe: <" + u + ">\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
		v := analyze(t, buildMessage(t, msgOpts{headers: h}), Options{Resolver: OfflineResolver{}})
		if c := checkOf(t, v, "unsub.one_click"); c.Status != verdict.Fail {
			t.Errorf("%s: unsub.one_click = %s", u, c.Status)
		}
	}
	h := "List-Unsubscribe: <https://e.example/u/*|UNSUB|*>\r\n"
	v := analyze(t, buildMessage(t, msgOpts{headers: h}), Options{Resolver: OfflineResolver{}})
	if c := checkOf(t, v, "content.placeholders"); c.Status != verdict.Fail {
		t.Errorf("content.placeholders = %s", c.Status)
	}
}

func FuzzAnalyze(f *testing.F) {
	f.Add(htmlMessage(`<a href="http://bit.ly/x">{{first_name}}<a>`))
	f.Add([]byte(plainHeaders + "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n"))
	f.Add([]byte("From: a@b\r\n\r\n"))
	f.Add([]byte("not a message"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		v, err := Analyze(ctx, raw, Options{Resolver: OfflineResolver{}})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("a parse error should not be a timeout")
			}
			return
		}
		if v.Verdict == "" || v.Summary == "" {
			t.Errorf("incomplete verdict: %+v", v)
		}
	})
}
