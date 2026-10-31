package engine

import (
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

func TestCorruptPlainTextDoesNotSkipGoodHTML(t *testing.T) {
	bad := func(a, b string) []byte {
		return []byte(plainHeaders + "Content-Type: multipart/alternative; boundary=b\r\n\r\n" + a + b + "--b--\r\n")
	}
	text := "--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!notbase64!!!\r\n"
	html := "--b\r\nContent-Type: text/html\r\n\r\n<p><a href=\"https://example.com/u\">unsubscribe</a> Hello there</p>\r\n"
	v := analyze(t, bad(text, html), Options{Resolver: goodDNS()})
	if c := checkOf(t, v, "content.placeholders"); c.Status == verdict.Skipped {
		t.Errorf("content.placeholders = %s %q", c.Status, c.Title)
	}
	// With no HTML, the corrupt text is all there is.
	v = analyze(t, bad(text, ""), Options{Resolver: goodDNS()})
	if c := checkOf(t, v, "content.placeholders"); c.Status != verdict.Skipped {
		t.Errorf("text only: content.placeholders = %s %q", c.Status, c.Title)
	}
}
