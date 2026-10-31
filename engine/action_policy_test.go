package engine

import (
	"net/http"
	"strings"
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

// Every entry here must stay unfetched, as a link or as a redirect target:
// following one can change someone's subscription.
func TestActionURLsAreNeverFetched(t *testing.T) {
	for _, u := range []string{
		"https://l.example/preference-center",
		"https://l.example/email-preference",
		"https://l.example/un-subscribe",
		"https://l.example/un_subscribe",
		"https://l.example/prefs",
		"https://l.example/verify?token=1",
		"https://l.example/verify-email/abc",
		"https://l.example/activate",
		"https://l.example/resubscribe",
		"https://l.example/subscribe?t=1",
		"https://l.example/settings/email",
		"https://l.example/%75n-subscribe",
		"https://l.example/opt_out",
		"https://l.example/opt-out",
		"https://l.example/disable_email",
	} {
		if !isActionLink(u, nil) {
			t.Errorf("%s is not an action link", u)
		}
		rt := &recordingClient{}
		analyze(t, htmlMessage(`<a href="`+u+`">Read the post</a>`), Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: rt}})
		if rt.asked("l.example") {
			t.Errorf("fetched %s", u)
		}

		rt = &recordingClient{do: func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "go.example" {
				res := status(302)
				res.Header = http.Header{"Location": {u}}
				return res, nil
			}
			return status(200), nil
		}}
		analyze(t, htmlMessage(`<a href="https://go.example/post">Read the post</a>`), Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: rt}})
		if rt.asked("l.example") {
			t.Errorf("redirect followed to %s", u)
		}
	}
}

func TestActionContextsAreNeverFetched(t *testing.T) {
	for name, raw := range map[string][]byte{
		"text line above":   []byte(plainHeaders + "Content-Type: text/plain\r\n\r\nUnsubscribe:\r\nhttps://l.example/opaque3\r\n"),
		"text blank above":  []byte(plainHeaders + "Content-Type: text/plain\r\n\r\nOpt out\r\n\r\nhttps://l.example/opaque3\r\n"),
		"block above":       htmlMessage(`<p>Unsubscribe here:</p><p><a href="https://l.example/opaque">this link</a></p>`),
		"aria label":        htmlMessage(`<a aria-label="Unsubscribe" href="https://l.example/opaque"><img src="cid:x"></a>`),
		"title":             htmlMessage(`<a title="Manage your subscription" href="https://l.example/opaque">Go</a>`),
		"same block":        htmlMessage(`<p>To unsubscribe <a href="https://l.example/opaque">click here</a></p>`),
		"tracker, here":     htmlMessage(`<a href="https://x.list-manage.com/track/abc">here</a>`),
		"tracker, no text":  []byte(plainHeaders + "Content-Type: text/plain\r\n\r\nhttps://ct.sendgrid.net/ls/click?upn=1\r\n"),
		"own tracker, here": htmlMessage(`<a href="https://email.mg.example.com/c/abc">click here</a>`),
		"foreign tracker":   htmlMessage(`<a href="https://em.other.example/c/abc">here</a>`),
	} {
		rt := &recordingClient{}
		analyze(t, raw, Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: rt}})
		if len(rt.urls) != 0 {
			t.Errorf("%s: fetched %v", name, rt.urls)
		}
	}
}

func TestClearLinksAreStillFetched(t *testing.T) {
	rt := &recordingClient{}
	raw := htmlMessage(`<p>Unsubscribe any time.</p><p><a href="https://l.example/posts/sun">Read about the sun</a></p>` +
		`<p><a href="https://click.l.example/c/abc">The full story</a></p>`)
	analyze(t, raw, Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: rt}})
	if !rt.asked("/posts/sun") || !rt.asked("/c/abc") {
		t.Errorf("fetched %v", rt.urls)
	}
}

func TestGetRetriesAFailedHead(t *testing.T) {
	for _, code := range []int{400, 500} {
		rt := &recordingClient{do: func(req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodHead {
				return status(code), nil
			}
			return status(200), nil
		}}
		v := analyze(t, htmlMessage(`<a href="https://l.example/post">Read</a>`), Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: rt}})
		if c := checkOf(t, v, "content.links"); c.Status != verdict.Pass {
			t.Errorf("HEAD %d: content.links = %s %q", code, c.Status, c.Title)
		}
	}
}

func TestNonStandardStatusIsNotBroken(t *testing.T) {
	rt := &recordingClient{do: func(*http.Request) (*http.Response, error) { return status(999), nil }}
	v := analyze(t, htmlMessage(`<a href="https://l.example/post">Read</a>`), Options{Resolver: goodDNS(), CheckLinks: true, HTTPClient: &http.Client{Transport: rt}})
	if c := checkOf(t, v, "content.links"); c.Status != verdict.Skipped {
		t.Errorf("content.links = %s %q", c.Status, c.Title)
	}
}

func TestVisibleUnsubscribeInSurroundingText(t *testing.T) {
	v := analyze(t, htmlMessage(`<p>To unsubscribe, <a href="https://l.example/opaque">click here</a></p>`), Options{Resolver: goodDNS()})
	if c := checkOf(t, v, "unsub.visible"); c.Status != verdict.Pass {
		t.Errorf("unsub.visible = %s %q", c.Status, c.Title)
	}
}

func TestLinkTextMismatchOnPublishingHosts(t *testing.T) {
	for name, tc := range map[string]struct {
		html string
		want verdict.Status
	}{
		"claimable name":  {`<a href="https://evil.ghost.io/l">paypal.com</a>`, verdict.Warn},
		"platform click":  {`<a href="https://link.mail.beehiiv.com/ss/c/abc">paypal.com</a>`, verdict.Pass},
		"platform path":   {`<a href="https://substack.com/redirect/abc">paypal.com</a>`, verdict.Pass},
		"majority no tie": {strings.Repeat(`<a href="https://evil.test/l">paypal.com</a> `, 3), verdict.Warn},
	} {
		v := analyze(t, htmlMessage(tc.html), Options{Resolver: goodDNS()})
		if c := checkOf(t, v, "content.link_text"); c.Status != tc.want {
			t.Errorf("%s: content.link_text = %s, want %s", name, c.Status, tc.want)
		}
	}
}
