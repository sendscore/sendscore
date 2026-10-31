package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/sendscore/sendscore/verdict"
)

// fakeDNS answers from maps; anything missing does not exist.
type fakeDNS struct {
	txt map[string][]string
	ptr map[string][]string
	ip  map[string][]net.IPAddr
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txt[strings.TrimSuffix(name, ".")]; ok {
		return v, nil
	}
	return nil, notFound(name)
}
func (f *fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, notFound(name)
}
func (f *fakeDNS) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if v, ok := f.ip[strings.TrimSuffix(host, ".")]; ok {
		return v, nil
	}
	return nil, notFound(host)
}
func (f *fakeDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if v, ok := f.ptr[addr]; ok {
		return v, nil
	}
	return nil, notFound(addr)
}

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

const sendIP = "203.0.113.10"

// goodDNS is a publisher who has done everything right.
func goodDNS() *fakeDNS {
	pub, _ := x509.MarshalPKIXPublicKey(&testKey.PublicKey)
	return &fakeDNS{
		txt: map[string][]string{
			"k1._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)},
			"_dmarc.example.com":        {"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"},
			"bounce.example.com":        {"v=spf1 ip4:203.0.113.0/24 -all"},
		},
		ptr: map[string][]string{sendIP: {"mail.example.net."}},
		ip: map[string][]net.IPAddr{
			"mail.example.net": {{IP: net.ParseIP(sendIP)}},
			// Each list's test domain is always listed.
			"dbltest.com.dbl.spamhaus.org":   {{IP: net.ParseIP("127.0.1.2")}},
			"test.surbl.org.multi.surbl.org": {{IP: net.ParseIP("127.0.0.126")}},
		},
	}
}

var publicLists = []Blocklist{SpamhausPublic(), SURBLPublic()}

const goodHTML = `<html><head><style>p{color:#333}</style></head><body>
<p>Hello. Today: shooting into the sun.</p>
<p>Shooting straight into the sun flattens contrast and blows out the sky, but a small change in angle fixes most of it. Put the sun just outside the frame, or behind something with a hard edge, and let the flare work for you instead of against you. Meter for the highlights, then lift the shadows later.</p>
<p><img src="https://cdn.example.com/sun.jpg" alt="A sunset" width="600" height="400"></p>
<p><a href="https://example.com/posts/sun">Read the full tip</a></p>
<p><a href="https://example.com/unsubscribe?u=1">Unsubscribe</a></p>
<img src="https://t.example.com/open.gif" width="1" height="1">
</body></html>`

type msgOpts struct {
	subject  string
	from     string
	headers  string
	html     string
	text     string
	sign     bool
	signKeys []string
	domain   string
}

func buildMessage(t *testing.T, o msgOpts) []byte {
	t.Helper()
	if o.from == "" {
		o.from = "Daily Tips <tips@example.com>"
	}
	if o.html == "" {
		o.html = goodHTML
	}
	if o.text == "" {
		o.text = "Hello. Today: shooting into the sun.\r\nUnsubscribe: https://example.com/unsubscribe?u=1\r\n"
	}
	if o.headers == "" {
		o.headers = "List-Unsubscribe: <https://example.com/unsubscribe?u=1>, <mailto:unsub@example.com>\r\n" +
			"List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
	}
	var b strings.Builder
	b.WriteString("Return-Path: <bounce@bounce.example.com>\r\n")
	b.WriteString("From: " + o.from + "\r\n")
	b.WriteString("To: test@in.sendscore.ai\r\n")
	if o.subject == "" {
		o.subject = "Shooting into the sun"
	}
	b.WriteString("Subject: " + o.subject + "\r\n")
	b.WriteString("Date: Tue, 28 Oct 2026 13:12:04 +0000\r\n")
	b.WriteString("Message-ID: <abc123@example.com>\r\n")
	b.WriteString(o.headers)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/alternative; boundary=\"b1\"\r\n\r\n")
	b.WriteString("--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + o.text + "\r\n")
	b.WriteString("--b1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + strings.ReplaceAll(o.html, "\n", "\r\n") + "\r\n")
	b.WriteString("--b1--\r\n")
	raw := []byte(b.String())
	if !o.sign {
		return raw
	}
	if o.domain == "" {
		o.domain = "example.com"
	}
	keys := o.signKeys
	if keys == nil {
		keys = []string{"From", "To", "Subject", "Date", "Message-ID", "List-Unsubscribe", "List-Unsubscribe-Post"}
	}
	var signed bytes.Buffer
	if err := dkim.Sign(&signed, bytes.NewReader(raw), &dkim.SignOptions{
		Domain: o.domain, Selector: "k1", Signer: testKey, HeaderKeys: keys,
	}); err != nil {
		t.Fatal(err)
	}
	return signed.Bytes()
}

func envelope() Envelope {
	tls := true
	return Envelope{RemoteIP: net.ParseIP(sendIP), Helo: "mail.example.net", MailFrom: "bounce@bounce.example.com", TLS: &tls}
}

func analyze(t *testing.T, raw []byte, opts Options) *verdict.Verdict {
	t.Helper()
	if opts.Resolver == nil {
		opts.Resolver = goodDNS()
	}
	v, err := Analyze(context.Background(), raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func find(t *testing.T, v *verdict.Verdict, id string) verdict.Check {
	t.Helper()
	for _, c := range v.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %s", id)
	return verdict.Check{}
}

func wantStatus(t *testing.T, v *verdict.Verdict, id string, want verdict.Status) {
	t.Helper()
	if c := find(t, v, id); c.Status != want {
		t.Errorf("%s = %s (%s %s), want %s", id, c.Status, c.Title, c.Reason, want)
	}
}

func TestEverythingRight(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Envelope: envelope(), Blocklists: publicLists})
	for _, id := range []string{
		"auth.dkim", "auth.dkim_key", "auth.spf", "auth.spf_lookups", "auth.dmarc_record",
		"auth.dmarc", "auth.alignment", "auth.ptr", "auth.tls",
		"unsub.header", "unsub.one_click", "unsub.signed", "unsub.visible",
		"struct.mime", "struct.plain_text", "struct.html_size", "struct.headers", "struct.from_domain",
		"content.placeholders", "content.insecure_links", "content.image_alt",
		"content.subject", "content.preheader", "content.text_ratio", "content.shorteners",
		"content.link_text", "content.active", "content.blocklists",
	} {
		wantStatus(t, v, id, verdict.Pass)
	}
	wantStatus(t, v, "content.links", verdict.Skipped)
	if v.Verdict != verdict.Pass || !v.ReadyToSend {
		t.Errorf("verdict = %s ready=%v, want pass and ready: %s", v.Verdict, v.ReadyToSend, v.Summary)
	}
	if len(v.TopFixes) != 0 {
		t.Errorf("top fixes = %v, want none", v.TopFixes)
	}
}

func TestProviderSignatureDoesNotAlign(t *testing.T) {
	dns := goodDNS()
	dns.txt["k1._domainkey.mailer.net"] = dns.txt["k1._domainkey.example.com"]
	dns.txt["bounces.mailer.net"] = []string{"v=spf1 ip4:203.0.113.0/24 -all"}
	// Signed by the platform, not the publisher, with the platform's
	// Return-Path, so SPF cannot help.
	raw := withReturnPath(buildMessage(t, msgOpts{sign: true, domain: "mailer.net"}), "bounce@bounces.mailer.net")
	v := analyze(t, raw, Options{Resolver: dns})
	wantStatus(t, v, "auth.dkim", verdict.Pass)
	wantStatus(t, v, "auth.dmarc", verdict.Fail)
	wantStatus(t, v, "auth.spf", verdict.Skipped)
	if v.ReadyToSend {
		t.Error("ready_to_send with DMARC failing")
	}
	if len(v.TopFixes) == 0 || v.TopFixes[0].Check != "auth.dmarc" {
		t.Errorf("first fix = %v, want auth.dmarc", v.TopFixes)
	}
}

func TestSPFAlignsOnlyWarns(t *testing.T) {
	dns := goodDNS()
	dns.txt["k1._domainkey.mailer.net"] = dns.txt["k1._domainkey.example.com"]
	v := analyze(t, buildMessage(t, msgOpts{sign: true, domain: "mailer.net"}), Options{Resolver: dns, Envelope: envelope()})
	wantStatus(t, v, "auth.dmarc", verdict.Pass)
	wantStatus(t, v, "auth.alignment", verdict.Warn)
}

func TestNoUnsubscribeHeaders(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true, headers: "X-Nothing: 1\r\n", signKeys: []string{"From", "Subject"}}), Options{Envelope: envelope()})
	wantStatus(t, v, "unsub.header", verdict.Fail)
	wantStatus(t, v, "unsub.one_click", verdict.Fail)
	wantStatus(t, v, "unsub.signed", verdict.Skipped)
	if v.ReadyToSend {
		t.Error("ready_to_send without List-Unsubscribe")
	}
}

func TestUnsubscribeNotSigned(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true, signKeys: []string{"From", "Subject", "Date"}}), Options{Envelope: envelope()})
	wantStatus(t, v, "unsub.header", verdict.Pass)
	wantStatus(t, v, "unsub.signed", verdict.Fail)
}

func TestUnsigned(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{}), Options{Envelope: envelope()})
	wantStatus(t, v, "auth.dkim", verdict.Fail)
	// SPF still aligns (bounce.example.com and example.com share an org domain).
	wantStatus(t, v, "auth.dmarc", verdict.Pass)
	wantStatus(t, v, "unsub.signed", verdict.Fail)
}

func TestTamperedBodyFailsDKIM(t *testing.T) {
	raw := buildMessage(t, msgOpts{sign: true})
	raw = bytes.Replace(raw, []byte("shooting into the sun."), []byte("shooting into the moon"), 1)
	v := analyze(t, raw, Options{Envelope: envelope()})
	wantStatus(t, v, "auth.dkim", verdict.Fail)
}

func TestNoDMARCRecord(t *testing.T) {
	dns := goodDNS()
	delete(dns.txt, "_dmarc.example.com")
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
	wantStatus(t, v, "auth.dmarc_record", verdict.Fail)
}

func TestDMARCOrgFallbackAndNoReports(t *testing.T) {
	dns := goodDNS()
	dns.txt["_dmarc.example.com"] = []string{"v=DMARC1; p=none"}
	dns.txt["k1._domainkey.news.example.com"] = dns.txt["k1._domainkey.example.com"]
	v := analyze(t, buildMessage(t, msgOpts{sign: true, from: "tips@news.example.com", domain: "news.example.com"}), Options{Resolver: dns})
	c := find(t, v, "auth.dmarc_record")
	if c.Status != verdict.Warn || c.Evidence["domain"] != "example.com" {
		t.Errorf("dmarc_record = %s %v, want warn found at example.com", c.Status, c.Evidence)
	}
}

func TestSPFLookupCount(t *testing.T) {
	dns := goodDNS()
	var incl []string
	for _, d := range []string{"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11"} {
		dns.txt[d+".example.org"] = []string{"v=spf1 -all"}
		incl = append(incl, "include:"+d+".example.org")
	}
	dns.txt["bounce.example.com"] = []string{"v=spf1 " + strings.Join(incl, " ") + " -all"}
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns})
	c := find(t, v, "auth.spf_lookups")
	if c.Status != verdict.Fail || c.Evidence["lookups"] != 11 {
		t.Errorf("spf_lookups = %s %v, want fail at 11", c.Status, c.Evidence)
	}
}

func TestPTRMismatch(t *testing.T) {
	dns := goodDNS()
	dns.ip["mail.example.net"] = []net.IPAddr{{IP: net.ParseIP("198.51.100.1")}}
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
	wantStatus(t, v, "auth.ptr", verdict.Fail)
	// The publisher cannot fix reverse DNS, but it is still a failure.
	if f := find(t, v, "auth.ptr").Fix; f == nil || f.Who != verdict.FixedByProvider {
		t.Errorf("ptr fix = %v, want provider", f)
	}
}

func TestOfflineSkipsDNSChecks(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: OfflineResolver{}})
	for _, id := range []string{"auth.dkim", "auth.spf", "auth.spf_lookups", "auth.dmarc_record", "auth.dmarc", "unsub.signed"} {
		wantStatus(t, v, id, verdict.Skipped)
	}
	wantStatus(t, v, "unsub.header", verdict.Pass)
}

func TestPlaceholders(t *testing.T) {
	html := strings.Replace(goodHTML, "Hello.", "Hello {{ subscriber.first_name }}, *|FNAME|*.", 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	c := find(t, v, "content.placeholders")
	if c.Status != verdict.Fail || len(c.Evidence["found"].([]string)) != 2 {
		t.Errorf("placeholders = %s %v", c.Status, c.Evidence)
	}
	// Content failures do not block sending by default.
	if !v.ReadyToSend && find(t, v, "auth.dmarc").Status == verdict.Pass {
		t.Error("a merge tag blocked ready_to_send")
	}
}

func TestCSSBracesAreNotPlaceholders(t *testing.T) {
	html := strings.Replace(goodHTML, "p{color:#333}", "@media{{}} .x{{color:red}}", 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.placeholders", verdict.Pass)
}

func TestGmailClipping(t *testing.T) {
	html := strings.Replace(goodHTML, "<p>Hello.", "<p>"+strings.Repeat("x", 110*1024)+"</p><p>Hello.", 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "struct.html_size", verdict.Fail)
}

func TestFreeMailboxFrom(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{from: "me@gmail.com"}), Options{Resolver: OfflineResolver{}})
	wantStatus(t, v, "struct.from_domain", verdict.Fail)
}

func TestImagesAndInsecureLinks(t *testing.T) {
	html := strings.Replace(goodHTML, `alt="A sunset" `, "", 1)
	html = strings.Replace(html, "https://example.com/posts/sun", "http://example.com/posts/sun", 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.image_alt", verdict.Warn)
	wantStatus(t, v, "content.insecure_links", verdict.Warn)
}

func TestCompareFlagsRegressions(t *testing.T) {
	dns := goodDNS()
	dns.txt["k1._domainkey.mailer.net"] = dns.txt["k1._domainkey.example.com"]
	prev := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns})
	cur := analyze(t, withReturnPath(buildMessage(t, msgOpts{sign: true, domain: "mailer.net", headers: "X-Nothing: 1\r\n", signKeys: []string{"From"}}), "bounce@bounces.mailer.net"),
		Options{Resolver: dns, Previous: prev.Fingerprint})

	fields := map[string]verdict.Change{}
	for _, c := range cur.Changes {
		fields[c.Field] = c
	}
	if fields["dkim.d"].After != "mailer.net" {
		t.Errorf("dkim.d change = %+v", fields["dkim.d"])
	}
	if fields["auth.dmarc"].Worsened != "auth.dmarc" {
		t.Errorf("auth.dmarc change = %+v", fields["auth.dmarc"])
	}
	if fields["unsub.list_unsubscribe"].Worsened != "unsub.header" {
		t.Errorf("unsubscribe change = %+v", fields["unsub.list_unsubscribe"])
	}
	wantStatus(t, cur, "changes.regressions", verdict.Warn)
}

func TestCompareSameIssueIsQuiet(t *testing.T) {
	a := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{})
	b := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Previous: a.Fingerprint})
	if len(b.Changes) != 0 {
		t.Errorf("changes = %+v, want none", b.Changes)
	}
}

func TestRejectsNonEmail(t *testing.T) {
	if _, err := Analyze(context.Background(), []byte("hello"), Options{Resolver: OfflineResolver{}}); err == nil {
		t.Error("parsed a non-email")
	}
}

func TestActionLinksAreNotFetched(t *testing.T) {
	for _, u := range []string{
		"https://example.com/unsubscribe?u=1",
		"https://example.com/subscription/confirm?t=x",
		"https://us1.list-manage.com/profile?u=1",
	} {
		if !isActionLink(u, nil) {
			t.Errorf("%s would be fetched", u)
		}
	}
	if isActionLink("https://example.com/posts/sun", nil) {
		t.Error("an ordinary link was treated as an action link")
	}
}

func TestSafeClientRefusesPrivateAddresses(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1"} {
		if publicIP(net.ParseIP(ip)) {
			t.Errorf("%s counted as public", ip)
		}
	}
	if !publicIP(net.ParseIP("93.184.215.14")) {
		t.Error("a public address was refused")
	}
}

func TestNoSPFRecordFails(t *testing.T) {
	dns := goodDNS()
	delete(dns.txt, "bounce.example.com")
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns})
	wantStatus(t, v, "auth.spf_lookups", verdict.Fail)
}

func TestSubjectSignals(t *testing.T) {
	long := strings.Repeat("Shooting into the sun, ", 4)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, subject: long}), Options{})
	wantStatus(t, v, "content.subject", verdict.Warn)
	v = analyze(t, buildMessage(t, msgOpts{sign: true, subject: "HUGE SALE ON LENSES TODAY!!"}), Options{})
	c := find(t, v, "content.subject")
	if c.Status != verdict.Warn || len(c.Evidence["issues"].([]string)) != 2 {
		t.Errorf("subject = %s %v", c.Status, c.Evidence)
	}
}

func TestPreheaderBoilerplate(t *testing.T) {
	html := strings.Replace(goodHTML, "<p>Hello.", "<p><a href=\"https://example.com/web\">View in browser</a></p><p>Hello.", 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.preheader", verdict.Warn)
}

func TestImageOnly(t *testing.T) {
	html := `<html><body><img src="https://cdn.example.com/a.jpg" alt="Sale"><img src="https://cdn.example.com/b.jpg" alt="More"><p><a href="https://example.com/unsubscribe?u=1">Unsubscribe</a></p></body></html>`
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.text_ratio", verdict.Warn)
}

func TestShortenersAndActiveContent(t *testing.T) {
	html := strings.Replace(goodHTML, "https://example.com/posts/sun", "https://bit.ly/3abc", 1)
	html = strings.Replace(html, "</body>", `<form action="https://example.com/poll"><input name="q"></form><script>x()</script></body>`, 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.shorteners", verdict.Warn)
	c := find(t, v, "content.active")
	if c.Status != verdict.Warn || len(c.Evidence["found"].([]string)) != 2 {
		t.Errorf("active = %s %v", c.Status, c.Evidence)
	}
}

func TestLinkTextMismatch(t *testing.T) {
	html := strings.Replace(goodHTML, "</body>", `<p><a href="https://evil.test/login">paypal.com</a></p></body>`, 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.link_text", verdict.Warn)

	// Click tracking: every link goes through one domain, so text naming
	// the real destination is normal.
	tracked := `<html><body><p>Hello there, a longer issue body follows here.</p>
<p><a href="https://click.mailer.test/a">example.com/posts/sun</a></p>
<p><a href="https://click.mailer.test/b">Read more</a></p>
<p><a href="https://click.mailer.test/c">Unsubscribe</a></p></body></html>`
	v = analyze(t, buildMessage(t, msgOpts{sign: true, html: tracked}), Options{})
	wantStatus(t, v, "content.link_text", verdict.Pass)
}

func TestBlocklists(t *testing.T) {
	dns := goodDNS()
	dns.ip["badlinks.test.dbl.spamhaus.org"] = []net.IPAddr{{IP: net.ParseIP("127.0.1.2")}}
	html := strings.Replace(goodHTML, "https://example.com/posts/sun", "https://www.badlinks.test/offer", 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{Resolver: dns, Blocklists: publicLists})
	c := find(t, v, "content.blocklists")
	if c.Status != verdict.Fail || !strings.Contains(c.Title, "badlinks.test") {
		t.Errorf("blocklists = %s %s", c.Status, c.Title)
	}
	// Content failures do not block sending by default.
	if !v.ReadyToSend {
		t.Error("a blocklisted link blocked ready_to_send")
	}
}

type refusingDNS struct{ *fakeDNS }

func (r refusingDNS) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if strings.HasSuffix(host, ".dbl.spamhaus.org") {
		return []net.IPAddr{{IP: net.ParseIP("127.255.255.254")}}, nil
	}
	if strings.HasSuffix(host, ".multi.surbl.org") {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	return r.fakeDNS.LookupIPAddr(ctx, host)
}

func TestBlocklistRefusalIsSkipped(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: refusingDNS{goodDNS()}, Blocklists: publicLists})
	c := find(t, v, "content.blocklists")
	if c.Status != verdict.Skipped || !strings.Contains(c.Reason, "refused") {
		t.Errorf("blocklists = %s %q", c.Status, c.Reason)
	}
}

func TestAttachmentsAreRecorded(t *testing.T) {
	raw := buildMessage(t, msgOpts{})
	raw = bytes.Replace(raw, []byte("--b1--"), []byte("--b1\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"issue.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n--b1--"), 1)
	v := analyze(t, raw, Options{Resolver: OfflineResolver{}})
	c := find(t, v, "content.active")
	if c.Status != verdict.Warn || !strings.Contains(c.Detail, "issue.pdf") || strings.Contains(c.Title, "issue.pdf") {
		t.Errorf("active = %s %q %q", c.Status, c.Title, c.Detail)
	}
}

func TestBlocklistsOffByDefault(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{})
	c := find(t, v, "content.blocklists")
	if c.Status != verdict.Skipped || !strings.Contains(c.Reason, "off") {
		t.Errorf("blocklists = %s %q", c.Status, c.Reason)
	}
}

func TestBlocklistIPLinksAreNotLookedUp(t *testing.T) {
	dns := goodDNS()
	// What DBL really answers for an IP address: an error code in its range.
	dns.ip["203.0.113.5.dbl.spamhaus.org"] = []net.IPAddr{{IP: net.ParseIP("127.0.1.255")}}
	html := strings.Replace(goodHTML, "https://example.com/posts/sun", "https://203.0.113.5/x", 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{Resolver: dns, Blocklists: publicLists})
	wantStatus(t, v, "content.blocklists", verdict.Pass)
}

// partialDNS refuses Spamhaus while SURBL answers normally.
type partialDNS struct{ *fakeDNS }

func (p partialDNS) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if strings.HasSuffix(host, ".dbl.spamhaus.org") {
		return []net.IPAddr{{IP: net.ParseIP("127.255.255.254")}}, nil
	}
	return p.fakeDNS.LookupIPAddr(ctx, host)
}

func TestBlocklistPartialRefusalIsNotAPass(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: partialDNS{goodDNS()}, Blocklists: publicLists})
	c := find(t, v, "content.blocklists")
	if c.Status != verdict.Skipped || !strings.Contains(c.Reason, "Spamhaus") {
		t.Errorf("blocklists = %s %q", c.Status, c.Reason)
	}
}

func TestBlocklistSilentResolverIsNotAPass(t *testing.T) {
	// A resolver that answers "no such name" for everything, including the
	// lists' test domains, has not checked anything.
	dns := goodDNS()
	delete(dns.ip, "dbltest.com.dbl.spamhaus.org")
	delete(dns.ip, "test.surbl.org.multi.surbl.org")
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Blocklists: publicLists})
	c := find(t, v, "content.blocklists")
	if c.Status != verdict.Skipped || !strings.Contains(c.Reason, "test lookup") {
		t.Errorf("blocklists = %s %q", c.Status, c.Reason)
	}
}

// failingDNS fails lookups for one domain, as a timeout would.
type failingDNS struct{ *fakeDNS }

func (f failingDNS) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if strings.HasPrefix(host, "example.com.") {
		return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
	}
	return f.fakeDNS.LookupIPAddr(ctx, host)
}

func TestBlocklistFailedLookupIsNotAPass(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: failingDNS{goodDNS()}, Blocklists: publicLists})
	c := find(t, v, "content.blocklists")
	if c.Status != verdict.Skipped || !strings.Contains(c.Reason, "example.com") {
		t.Errorf("blocklists = %s %q", c.Status, c.Reason)
	}
}

func TestBlocklistTooManyDomainsIsNotAPass(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxBlocklistDomains+5; i++ {
		fmt.Fprintf(&b, `<p><a href="https://site%03d.test/">Read more</a></p>`, i)
	}
	html := strings.Replace(goodHTML, "</body>", b.String()+"</body>", 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{Blocklists: publicLists})
	c := find(t, v, "content.blocklists")
	if c.Status != verdict.Skipped || c.Evidence["not_checked"] == nil {
		t.Errorf("blocklists = %s %q", c.Status, c.Reason)
	}
}

func TestLinkTextSingleMismatchIsFlagged(t *testing.T) {
	html := `<html><body><p>Your account needs attention before Friday, so please sign in and check it.</p>
<p><a href="https://evil.test/login">paypal.com</a></p></body></html>`
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.link_text", verdict.Warn)
}

func TestLinkTextIgnoresFileAndTechNames(t *testing.T) {
	html := strings.Replace(goodHTML, "</body>", `<p><a href="https://nodejs.org/">Node.js</a> and <a href="https://example.com/r">report.pdf</a> and <a href="https://example.com/x"><img src="https://cdn.example.com/h.jpg" alt="header.jpg"></a> and <a href="https://github.com/a/b">README.md</a></p></body>`, 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.link_text", verdict.Pass)
}

func TestLinkTextIsDeterministic(t *testing.T) {
	// Two domains with two links each: no tracking domain, so the result
	// must be the same every run.
	html := `<html><body><p>A short issue with four links to two places, for this test.</p>
<p><a href="https://brand-a.com/1">brand-b.com</a> <a href="https://brand-a.com/2">two</a> <a href="https://brand-b.com/1">three</a> <a href="https://brand-b.com/2">four</a></p></body></html>`
	raw := buildMessage(t, msgOpts{sign: true, html: html})
	first := find(t, analyze(t, raw, Options{}), "content.link_text").Status
	for i := 0; i < 50; i++ {
		if got := find(t, analyze(t, raw, Options{}), "content.link_text").Status; got != first {
			t.Fatalf("run %d = %s, first run = %s", i, got, first)
		}
	}
	if first != verdict.Warn {
		t.Errorf("link_text = %s, want warn", first)
	}
}

func TestLinkTextKnownTrackerIsAllowed(t *testing.T) {
	html := strings.Replace(goodHTML, "</body>", `<p><a href="https://click.convertkit-mail.com/abc">example.com/posts/sun</a></p></body>`, 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.link_text", verdict.Pass)
}

func TestPreheaderIgnoresTheTitle(t *testing.T) {
	html := `<html><head><title>Weekly Digest</title></head><body><p><a href="https://example.com/web">View this email in your browser</a></p><p>Hello there.</p></body></html>`
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.preheader", verdict.Warn)
}

func TestJSONLDIsNotActiveContent(t *testing.T) {
	html := strings.Replace(goodHTML, "</body>", `<script type="application/ld+json">{"@context":"http://schema.org"}</script></body>`, 1)
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.active", verdict.Pass)
}

func TestOnePhotoWithAParagraphIsNotImageOnly(t *testing.T) {
	html := `<html><body><img src="https://cdn.example.com/sun.jpg" alt="Sunset"><p>Shoot into the sun with the sun just outside the frame.</p><p><a href="https://example.com/unsubscribe?u=1">Unsubscribe</a></p></body></html>`
	v := analyze(t, buildMessage(t, msgOpts{sign: true, html: html}), Options{})
	wantStatus(t, v, "content.text_ratio", verdict.Pass)
}

func TestSubjectTitleReadsAsASentence(t *testing.T) {
	subj := "HUGE SALE ON EVERY LENS AND EVERY CAMERA BODY IN THE STORE THIS WEEKEND ONLY!!"
	v := analyze(t, buildMessage(t, msgOpts{sign: true, subject: subj}), Options{})
	c := find(t, v, "content.subject")
	want := "The subject line runs 78 characters, past the 70 a phone shows, is written in capitals, and has 2 exclamation marks"
	if c.Title != want {
		t.Errorf("title = %q\nwant    %q", c.Title, want)
	}
}

func TestTruncateKeepsWholeCharacters(t *testing.T) {
	got := truncate(strings.Repeat("é", 50), 40)
	if strings.ContainsRune(got, '\uFFFD') || len([]rune(got)) != 43 {
		t.Errorf("truncate = %q", got)
	}
}
