package engine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/sendscore/sendscore/verdict"
)

// failKey fails lookups of one name with a temporary error.
type failKey struct {
	*fakeDNS
	name string
}

func (f failKey) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if strings.TrimSuffix(name, ".") == f.name {
		return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
	}
	return f.fakeDNS.LookupTXT(ctx, name)
}

func signWith(t *testing.T, raw []byte, domain, selector string, key *rsa.PrivateKey, headers []string) []byte {
	t.Helper()
	return signAgain(t, raw, &dkim.SignOptions{Domain: domain, Selector: selector, Signer: key, HeaderKeys: headers})
}

func TestMixedDKIMResults(t *testing.T) {
	k2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k2.PublicKey)
	wrong, _ := x509.MarshalPKIXPublicKey(&testKey.PublicKey)
	key := func(b []byte) []string { return []string{"v=DKIM1; p=" + base64.StdEncoding.EncodeToString(b)} }
	base := []byte(plainHeaders + "Content-Type: text/plain\r\n\r\nhello unsubscribe\r\n")
	raw := signWith(t, base, "example.com", "k1", testKey, []string{"From", "Subject", "List-Unsubscribe", "List-Unsubscribe-Post"})
	raw = signWith(t, raw, "esp.example", "k2", k2, []string{"From", "Subject"})

	// The platform's signature passes without covering the headers, and
	// the one that covers them cannot be looked up.
	dns := goodDNS()
	dns.txt["k2._domainkey.esp.example"] = key(der)
	v := analyze(t, raw, Options{Resolver: failKey{dns, "k1._domainkey.example.com"}, Envelope: envelope()})
	if c := checkOf(t, v, "unsub.signed"); c.Status != verdict.Skipped {
		t.Errorf("unsub.signed = %s", c.Status)
	}

	// The platform's signature fails, and the other cannot be looked up.
	dns.txt["k2._domainkey.esp.example"] = key(wrong)
	v = analyze(t, raw, Options{Resolver: failKey{dns, "k1._domainkey.example.com"}, Envelope: envelope()})
	if c := checkOf(t, v, "auth.dkim"); c.Status != verdict.Skipped {
		t.Errorf("auth.dkim = %s", c.Status)
	}
}

func TestEmptySPFIdentity(t *testing.T) {
	raw := []byte(strings.Replace(string(htmlMessage("<p>hi</p>")), "Return-Path: <b@bounce.example.com>\r\n", "", 1))
	v := analyze(t, raw, Options{Resolver: goodDNS(), Envelope: Envelope{RemoteIP: net.ParseIP(sendIP)}})
	if c := checkOf(t, v, "auth.spf"); c.Status != verdict.Skipped {
		t.Errorf("auth.spf = %s %q", c.Status, c.Title)
	}
	// A draft with no envelope and no Return-Path says nothing about SPF.
	v = analyze(t, raw, Options{Resolver: goodDNS()})
	if c := checkOf(t, v, "auth.dmarc"); c.Status != verdict.Skipped {
		t.Errorf("auth.dmarc = %s %q", c.Status, c.Title)
	}
}

// stopAfterPTR cancels the analysis during the last authentication lookup.
type stopAfterPTR struct {
	*fakeDNS
	cancel func()
}

func (s stopAfterPTR) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if host == "mail.example.net" {
		s.cancel()
	}
	return s.fakeDNS.LookupIPAddr(ctx, host)
}

func TestStoppedAnalysisIsNotAPass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v, err := Analyze(ctx, buildMessage(t, msgOpts{sign: true}), Options{Resolver: stopAfterPTR{goodDNS(), cancel}, Envelope: envelope()})
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict == verdict.Pass || v.ReadyToSend || !strings.Contains(v.Summary, "stopped") {
		t.Errorf("verdict %s, ready %v, summary %q", v.Verdict, v.ReadyToSend, v.Summary)
	}
}

func TestMoreThanOneFromIsNotDMARCPass(t *testing.T) {
	for name, from := range map[string]string{
		"list":    "a@example.com, b@other.example",
		"headers": "a@example.com\r\nFrom: b@other.example",
	} {
		v := analyze(t, buildMessage(t, msgOpts{from: from, sign: true}), Options{Resolver: goodDNS(), Envelope: envelope()})
		if c := checkOf(t, v, "auth.dmarc"); c.Status != verdict.Skipped {
			t.Errorf("%s: auth.dmarc = %s", name, c.Status)
		}
		if v.ReadyToSend {
			t.Errorf("%s: ready to send", name)
		}
	}
}

func TestDMARCSyntaxErrorKeepsThePolicy(t *testing.T) {
	dns := goodDNS()
	dns.txt["_dmarc.example.com"] = []string{"v=DMARC1; p=reject; pct=abc"}
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
	if c := checkOf(t, v, "auth.dmarc_record"); c.Status != verdict.Warn {
		t.Errorf("auth.dmarc_record = %s", c.Status)
	}
	if c := checkOf(t, v, "auth.dmarc"); c.Status != verdict.Pass {
		t.Errorf("auth.dmarc = %s", c.Status)
	}
	dns.txt["_dmarc.example.com"] = []string{"v=DMARC1; p=bogus"}
	v = analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
	if c := checkOf(t, v, "auth.dmarc_record"); c.Status != verdict.Fail {
		t.Errorf("unusable policy: auth.dmarc_record = %s", c.Status)
	}
}

// stallDNS never answers until its context ends.
type stallDNS struct{ *fakeDNS }

func (stallDNS) LookupTXT(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stallDNS) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stallDNS) LookupAddr(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestStalledDNSCannotHoldTheAnalysis(t *testing.T) {
	l, a := lookupTimeout, authDeadline
	lookupTimeout, authDeadline = 20*time.Millisecond, 100*time.Millisecond
	defer func() { lookupTimeout, authDeadline = l, a }()
	start := time.Now()
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: stallDNS{goodDNS()}, Envelope: envelope()})
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	if c := checkOf(t, v, "auth.dmarc"); c.Status == verdict.Pass || c.Status == verdict.Fail {
		t.Errorf("auth.dmarc = %s", c.Status)
	}
	if v.ReadyToSend {
		t.Error("ready to send with no DNS answers")
	}
}
