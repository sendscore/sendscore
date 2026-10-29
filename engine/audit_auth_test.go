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
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/sendscore/sendscore/verdict"
)

// withReturnPath replaces the Return-Path buildMessage writes, which no
// signature covers.
func withReturnPath(raw []byte, addr string) []byte {
	return bytes.Replace(raw, []byte("Return-Path: <bounce@bounce.example.com>"), []byte("Return-Path: <"+addr+">"), 1)
}

// errDNS answers from fakeDNS, but returns err for the TXT or IP names in
// fail.
type errDNS struct {
	*fakeDNS
	fail map[string]bool
	err  error
	ips  int
}

func (d *errDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if d.fail[strings.TrimSuffix(name, ".")] {
		return nil, d.err
	}
	return d.fakeDNS.LookupTXT(ctx, name)
}

func (d *errDNS) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	d.ips++
	if d.fail[strings.TrimSuffix(host, ".")] {
		return nil, d.err
	}
	return d.fakeDNS.LookupIPAddr(ctx, host)
}

func serverFailure(name string) error {
	return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
}

func rsaRecord(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)
}

func signAgain(t *testing.T, raw []byte, o *dkim.SignOptions) []byte {
	t.Helper()
	if o.HeaderKeys == nil {
		o.HeaderKeys = []string{"From", "To", "Subject", "Date", "Message-ID", "List-Unsubscribe", "List-Unsubscribe-Post"}
	}
	var out bytes.Buffer
	if err := dkim.Sign(&out, bytes.NewReader(raw), o); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func hasRetryFix(v *verdict.Verdict) bool {
	for _, f := range v.TopFixes {
		if strings.HasPrefix(f.Fix, "Run the check again") {
			return true
		}
	}
	return false
}

func TestPTRForwardLookupFailureIsSkipped(t *testing.T) {
	dns := &errDNS{fakeDNS: goodDNS(), fail: map[string]bool{"mail.example.net": true}, err: serverFailure("mail.example.net")}
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
	wantStatus(t, v, "auth.ptr", verdict.Skipped)
	if !v.ReadyToSend {
		t.Errorf("not ready: %s", v.Summary)
	}
}

func TestPTRNamesAreCapped(t *testing.T) {
	dns := &errDNS{fakeDNS: goodDNS()}
	var names []string
	for i := 0; i < 500; i++ {
		names = append(names, fmt.Sprintf("h%d.example.net.", i))
	}
	dns.ptr[sendIP] = names
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
	c := find(t, v, "auth.ptr")
	if c.Status != verdict.Fail || c.Evidence["ptr_total"] != 500 || len(c.Evidence["ptr"].([]string)) != maxEvidenceItems {
		t.Errorf("ptr = %s %v", c.Status, c.Evidence["ptr_total"])
	}
	// SPF and the blocklists look up addresses too, but only a few.
	if dns.ips > maxPTRNames+5 {
		t.Errorf("%d address lookups, want about %d", dns.ips, maxPTRNames)
	}
}

func TestDKIMLookupErrorsAreNotBrokenSignatures(t *testing.T) {
	for name, err := range map[string]error{
		"canceled": &net.DNSError{Err: "operation was canceled", Name: "k1._domainkey.example.com"},
		"refused":  &net.DNSError{Err: "server misbehaving", Name: "k1._domainkey.example.com"},
		"context":  context.Canceled,
		"timeout":  context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			dns := &errDNS{fakeDNS: goodDNS(), fail: map[string]bool{"k1._domainkey.example.com": true}, err: err}
			v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
			wantStatus(t, v, "auth.dkim", verdict.Skipped)
			wantStatus(t, v, "unsub.signed", verdict.Skipped)
		})
	}
}

func TestDKIMUnknownIsNotReadyEvenWhenSPFAligns(t *testing.T) {
	dns := tempDNS{fakeDNS: goodDNS(), fail: map[string]bool{"k1._domainkey.example.com": true}}
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
	wantStatus(t, v, "auth.dkim", verdict.Skipped)
	wantStatus(t, v, "auth.dmarc", verdict.Pass)
	wantStatus(t, v, "auth.alignment", verdict.Skipped)
	if v.ReadyToSend || v.Verdict == verdict.Pass {
		t.Errorf("verdict = %s ready=%v, want not ready", v.Verdict, v.ReadyToSend)
	}
	if len(v.TopFixes) == 0 || v.TopFixes[0].Check != "auth.dkim" || !hasRetryFix(v) {
		t.Errorf("top fixes = %v, want a retry first", v.TopFixes)
	}
	for _, f := range v.TopFixes {
		if strings.Contains(f.Fix, "Set up DKIM") {
			t.Errorf("top fix %q tells them to set up DKIM they already have", f.Fix)
		}
	}
}

func TestNoEnvelopeAlignedReturnPathIsNotADMARCFailure(t *testing.T) {
	dns := goodDNS()
	dns.txt["k1._domainkey.mailer.net"] = dns.txt["k1._domainkey.example.com"]
	v := analyze(t, buildMessage(t, msgOpts{sign: true, domain: "mailer.net"}), Options{Resolver: dns})
	c := find(t, v, "auth.dmarc")
	if c.Status != verdict.Skipped || !strings.Contains(c.Reason, "no envelope") {
		t.Errorf("dmarc = %s %q", c.Status, c.Reason)
	}
	if v.ReadyToSend {
		t.Error("ready_to_send with DMARC unknown")
	}
	if hasRetryFix(v) || strings.Contains(v.Summary, "DNS") {
		t.Errorf("a missing envelope is not a DNS failure: %q %v", v.Summary, v.TopFixes)
	}
}

func TestWeakProviderKeyIsNotYours(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	dns := goodDNS()
	dns.txt["k2._domainkey.mailer.net"] = []string{rsaRecord(t, weak)}

	both := signAgain(t, buildMessage(t, msgOpts{sign: true}), &dkim.SignOptions{Domain: "mailer.net", Selector: "k2", Signer: weak})
	v := analyze(t, both, Options{Resolver: dns, Envelope: envelope()})
	if c := find(t, v, "auth.dkim_key"); c.Status != verdict.Pass || c.Evidence["weakest_rsa_bits"] != 2048 {
		t.Errorf("dkim_key = %s %v, want the publisher's 2048-bit key", c.Status, c.Evidence)
	}

	only := signAgain(t, buildMessage(t, msgOpts{}), &dkim.SignOptions{Domain: "mailer.net", Selector: "k2", Signer: weak})
	v = analyze(t, only, Options{Resolver: dns, Envelope: envelope()})
	c := find(t, v, "auth.dkim_key")
	if c.Status != verdict.Warn || c.Fix == nil || c.Fix.Who != verdict.FixedByProvider {
		t.Errorf("dkim_key = %s %v, want a warning for the provider", c.Status, c.Fix)
	}
}

func TestSPFLookupsAttribution(t *testing.T) {
	dns := goodDNS()
	var incl []string
	for i := 1; i <= 11; i++ {
		d := fmt.Sprintf("a%d.esp.test", i)
		dns.txt[d] = []string{"v=spf1 -all"}
		incl = append(incl, "include:"+d)
	}
	dns.txt["bounces.esp.test"] = []string{"v=spf1 " + strings.Join(incl, " ") + " -all"}
	v := analyze(t, withReturnPath(buildMessage(t, msgOpts{sign: true}), "b@bounces.esp.test"), Options{Resolver: dns})
	if c := find(t, v, "auth.spf_lookups"); c.Status != verdict.Fail || c.Fix == nil || c.Fix.Who != verdict.FixedByProvider {
		t.Errorf("spf_lookups = %s %v, want a fail for the provider", c.Status, c.Fix)
	}

	dns = goodDNS()
	delete(dns.txt, "bounce.example.com")
	v = analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns})
	if c := find(t, v, "auth.spf_lookups"); c.Status != verdict.Fail || c.Fix == nil || c.Fix.Who != verdict.FixedByYou {
		t.Errorf("spf_lookups = %s %v, want a fail for you", c.Status, c.Fix)
	}
}

func TestNoFromDomainIsNotADNSFailure(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true, from: "undisclosed"}), Options{Envelope: envelope()})
	rec := find(t, v, "auth.dmarc_record")
	if rec.Status != verdict.Skipped || strings.Contains(rec.Reason, "DNS") {
		t.Errorf("dmarc_record = %s %q", rec.Status, rec.Reason)
	}
	wantStatus(t, v, "auth.dmarc", verdict.Skipped)
	wantStatus(t, v, "struct.from_domain", verdict.Skipped)
	if hasRetryFix(v) || strings.Contains(v.Summary, "DNS") {
		t.Errorf("no From domain is not a DNS failure: %q %v", v.Summary, v.TopFixes)
	}
}

func TestInjectedListUnsubscribe(t *testing.T) {
	raw := buildMessage(t, msgOpts{sign: true})
	raw = append([]byte("List-Unsubscribe: <https://evil.test/x>\r\n"), raw...)
	v := analyze(t, raw, Options{Envelope: envelope()})
	c := find(t, v, "unsub.header")
	if c.Status != verdict.Fail || c.Evidence["headers"] != 2 {
		t.Errorf("unsub.header = %s %v, want a fail for two headers", c.Status, c.Evidence)
	}
	if uris := c.Evidence["uris"].([]string); len(uris) == 0 || uris[0] != "https://example.com/unsubscribe?u=1" {
		t.Errorf("uris = %v, want the signed instance", uris)
	}
	if v.ReadyToSend {
		t.Error("ready_to_send with two List-Unsubscribe headers")
	}
}

func TestListUnsubscribeURIsAreCapped(t *testing.T) {
	var uris []string
	for i := 0; i < 30; i++ {
		uris = append(uris, fmt.Sprintf("<mailto:u%d@example.com>", i))
	}
	h := "List-Unsubscribe: " + strings.Join(uris, ", ") + "\r\n"
	v := analyze(t, buildMessage(t, msgOpts{sign: true, headers: h}), Options{Envelope: envelope()})
	c := find(t, v, "unsub.header")
	if c.Evidence["uris_total"] != 30 || len(c.Evidence["uris"].([]string)) != maxEvidenceItems {
		t.Errorf("evidence = %v", c.Evidence)
	}
}

func TestDKIMExpiryUsesReceivedAt(t *testing.T) {
	raw := signAgain(t, buildMessage(t, msgOpts{}), &dkim.SignOptions{
		Domain: "example.com", Selector: "k1", Signer: testKey, Expiration: time.Now().Add(-time.Hour),
	})
	v := analyze(t, raw, Options{Envelope: envelope(), ReceivedAt: time.Now().Add(-48 * time.Hour)})
	wantStatus(t, v, "auth.dkim", verdict.Skipped)
	wantStatus(t, v, "unsub.signed", verdict.Skipped)
	if hasRetryFix(v) {
		t.Errorf("an expired signature is not a DNS failure: %v", v.TopFixes)
	}

	v = analyze(t, raw, Options{Envelope: envelope()})
	wantStatus(t, v, "auth.dkim", verdict.Fail)
}

func TestFreeMailboxDetailDoesNotClaimAPolicy(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{from: "me@gmail.com"}), Options{Resolver: OfflineResolver{}})
	if c := find(t, v, "struct.from_domain"); strings.Contains(c.Detail, "strict") {
		t.Errorf("detail = %q", c.Detail)
	}
}

func TestCompareReportsAuthNoLongerChecked(t *testing.T) {
	prev := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Envelope: envelope()})
	dns := tempDNS{fakeDNS: goodDNS(), fail: map[string]bool{"k1._domainkey.example.com": true}}
	cur := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope(), Previous: prev.Fingerprint})
	var got *verdict.Change
	for i, c := range cur.Changes {
		if c.Field == "auth.dkim" {
			got = &cur.Changes[i]
		}
	}
	if got == nil || got.After != verdict.Skipped || got.Worsened != "" {
		t.Errorf("auth.dkim change = %+v, want pass to skipped, not worsened", got)
	}
	for _, c := range cur.Checks {
		if c.ID == "changes.regressions" {
			t.Errorf("regressions = %q", c.Title)
		}
	}
}
