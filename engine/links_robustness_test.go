package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

func TestLinkTruncationIsNotAPass(t *testing.T) {
	var links strings.Builder
	for i := range 150 {
		fmt.Fprintf(&links, `<a href="https://l.example/p%d">x</a> `, i)
	}
	v := analyze(t, htmlMessage(links.String()), Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: &recordingClient{}}})
	c := checkOf(t, v, "content.links")
	if c.Status != verdict.Info || !strings.Contains(c.Title, "first 100 of 150") {
		t.Errorf("content.links = %s %q", c.Status, c.Title)
	}
}

func TestDisguisedActionLinksAreNotFetched(t *testing.T) {
	cases := map[string]struct{ raw []byte }{
		"image":  {htmlMessage(`<img src="https://l.example/unsubscribe?u=1" alt="x" width="600" height="400">`)},
		"escape": {htmlMessage(`<a href="https://l.example/%75nsubscribe">Read</a>`)},
		"badesc": {htmlMessage(`<a href="https://l.example/%75nsubscribe?q=%zz">Read</a>`)},
		"twice":  {htmlMessage(`<a href="https://l.example/%2575nsubscribe">Read</a>`)},
		"plain":  {[]byte(plainHeaders + "Content-Type: text/plain\r\n\r\nunsubscribe at https://l.example/y/ZZ\r\nnext line\r\n")},
		"before": {htmlMessage(`<p>To unsubscribe <a href="https://l.example/opaque">click here</a></p>`)},
		"after":  {htmlMessage(`<p>Click <a href="https://l.example/opaque">here</a> to unsubscribe</p>`)},
	}
	for name, c := range cases {
		rt := &recordingClient{}
		analyze(t, c.raw, Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: rt}})
		if rt.asked("l.example") {
			t.Errorf("%s: fetched %v", name, rt.urls)
		}
	}
}

func TestOtherLinksInABlockAreStillFetched(t *testing.T) {
	rt := &recordingClient{}
	raw := htmlMessage(`<p><a href="https://l.example/read">Read this</a></p><p>To unsubscribe <a href="https://l.example/opaque">click here</a></p>`)
	analyze(t, raw, Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: rt}})
	if !rt.asked("/read") || rt.asked("/opaque") {
		t.Errorf("fetched %v", rt.urls)
	}
}

func TestInconclusiveLinksAreNotBroken(t *testing.T) {
	cases := map[string]func(*http.Request) (*http.Response, error){
		"dns": func(*http.Request) (*http.Response, error) {
			return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
		},
		"timeout": func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded },
		"busy":    func(*http.Request) (*http.Response, error) { return status(429), nil },
		"wall":    func(*http.Request) (*http.Response, error) { return status(403), nil },
	}
	raw := htmlMessage(`<a href="https://l.example/a">Read</a>`)
	for name, do := range cases {
		v := analyze(t, raw, Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: &recordingClient{do: do}}})
		if c := checkOf(t, v, "content.links"); c.Status != verdict.Skipped {
			t.Errorf("%s: content.links = %s %q", name, c.Status, c.Title)
		}
	}
	for name, do := range map[string]func(*http.Request) (*http.Response, error){
		"404": func(*http.Request) (*http.Response, error) { return status(404), nil },
		"nxdomain": func(*http.Request) (*http.Response, error) {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		},
	} {
		v := analyze(t, raw, Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: &recordingClient{do: do}}})
		if c := checkOf(t, v, "content.links"); c.Status != verdict.Fail {
			t.Errorf("%s: content.links = %s", name, c.Status)
		}
	}
}

func TestHeadBusyIsRetriedWithGet(t *testing.T) {
	rt := &recordingClient{do: func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodHead {
			return status(503), nil
		}
		return status(200), nil
	}}
	v := analyze(t, htmlMessage(`<a href="https://l.example/a">Read</a>`), Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: rt}})
	if c := checkOf(t, v, "content.links"); c.Status != verdict.Pass {
		t.Errorf("content.links = %s", c.Status)
	}
}

func TestSpecialIPv6IsNotPublic(t *testing.T) {
	for _, s := range []string{"::127.0.0.1", "::10.0.0.1", "::ffff:0:127.0.0.1", "::2", "1::1", "4000::1"} {
		if publicIP(net.ParseIP(s)) {
			t.Errorf("%s reads as public", s)
		}
	}
	if !publicIP(net.ParseIP("2606:4700::1")) {
		t.Error("a global address reads as non-public")
	}
}

func TestOfflineFetchesNoLinks(t *testing.T) {
	v := analyze(t, htmlMessage(`<a href="http://localhost:9/x">Read</a>`), Options{Resolver: OfflineResolver{}, CheckLinks: true})
	if c := checkOf(t, v, "content.links"); c.Status != verdict.Skipped || !strings.Contains(c.Reason, "Offline") {
		t.Errorf("content.links = %s %q", c.Status, c.Reason)
	}
}
