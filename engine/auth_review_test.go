package engine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

// tempDNS answers from fakeDNS, but times out for the names in fail, or for
// every TXT name when all is set.
type tempDNS struct {
	*fakeDNS
	fail map[string]bool
	all  bool
}

func (d tempDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if d.all || d.fail[strings.TrimSuffix(name, ".")] {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return d.fakeDNS.LookupTXT(ctx, name)
}

// countingDNS gives every name an SPF record with twenty new includes, and
// counts the TXT lookups.
type countingDNS struct {
	*fakeDNS
	n int
}

func (d *countingDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".")
	if strings.HasPrefix(name, "_dmarc.") || strings.Contains(name, "._domainkey.") {
		return d.fakeDNS.LookupTXT(ctx, name)
	}
	d.n++
	var incl []string
	for i := 0; i < 20; i++ {
		incl = append(incl, fmt.Sprintf("include:i%d.%s", i, name))
	}
	return []string{"v=spf1 " + strings.Join(incl, " ") + " -all"}, nil
}

func spfLookups(t *testing.T, dns Resolver) verdict.Check {
	t.Helper()
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns})
	return find(t, v, "auth.spf_lookups")
}

func TestAuthUncheckedIsNotReady(t *testing.T) {
	for name, dns := range map[string]Resolver{
		"offline":  OfflineResolver{},
		"servfail": tempDNS{fakeDNS: goodDNS(), all: true},
	} {
		t.Run(name, func(t *testing.T) {
			v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
			wantStatus(t, v, "auth.dmarc", verdict.Skipped)
			wantStatus(t, v, "auth.alignment", verdict.Skipped)
			if v.ReadyToSend || v.Verdict == verdict.Pass {
				t.Errorf("verdict = %s ready=%v, want not ready and not pass", v.Verdict, v.ReadyToSend)
			}
			if !strings.HasPrefix(v.Summary, "Authentication could not be checked") {
				t.Errorf("summary = %q", v.Summary)
			}
			if len(v.TopFixes) == 0 || v.TopFixes[0].Check != "auth.dmarc" || !strings.HasPrefix(v.TopFixes[0].Fix, "Run the check again") {
				t.Errorf("top fixes = %v, want a retry first", v.TopFixes)
			}
		})
	}
}

func TestOfflineWithEnvelopeSkipsSPF(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: OfflineResolver{}, Envelope: envelope()})
	for _, id := range []string{"auth.spf", "auth.spf_lookups", "auth.dmarc", "auth.ptr"} {
		wantStatus(t, v, id, verdict.Skipped)
	}
	if r := find(t, v, "auth.spf").Reason; !strings.Contains(r, "Offline") {
		t.Errorf("spf reason = %q", r)
	}
}

func TestSPFLookupsStopAtTheLimit(t *testing.T) {
	dns := &countingDNS{fakeDNS: goodDNS()}
	c := spfLookups(t, dns)
	if c.Status != verdict.Fail || c.Title != "SPF needs more than 10 DNS lookups" {
		t.Errorf("spf_lookups = %s %q", c.Status, c.Title)
	}
	if dns.n > spfLookupLimit+1 {
		t.Errorf("made %d TXT lookups, want at most %d", dns.n, spfLookupLimit+1)
	}
}

func TestSPFSharedIncludeIsCountedOnEachPath(t *testing.T) {
	dns := goodDNS()
	dns.txt["bounce.example.com"] = []string{"v=spf1 include:x.example.org include:y.example.org -all"}
	dns.txt["x.example.org"] = []string{"v=spf1 include:z.example.org -all"}
	dns.txt["y.example.org"] = []string{"v=spf1 include:z.example.org -all"}
	dns.txt["z.example.org"] = []string{"v=spf1 a a:h1.example.org a:h2.example.org exists:h3.example.org a:h4.example.org -all"}
	for _, h := range []string{"z.example.org", "h1.example.org", "h2.example.org", "h3.example.org", "h4.example.org"} {
		dns.ip[h] = []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}
	}
	c := spfLookups(t, dns)
	if c.Status != verdict.Fail || c.Evidence["lookups"] != 11 {
		t.Errorf("spf_lookups = %s %q %v, want fail past 10", c.Status, c.Title, c.Evidence)
	}
}

func TestSPFPermanentErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		txt   map[string][]string
		title string
	}{
		"include without SPF": {
			txt:   map[string][]string{"bounce.example.com": {"v=spf1 include:typo.example.org ip4:203.0.113.0/24 -all"}},
			title: "SPF includes typo.example.org, which has no SPF record",
		},
		"two records": {
			txt:   map[string][]string{"bounce.example.com": {"v=spf1 ip4:203.0.113.0/24 -all", "v=spf1 -all"}},
			title: "More than one SPF record for bounce.example.com",
		},
		"void lookups": {
			txt:   map[string][]string{"bounce.example.com": {"v=spf1 a:v1.example.org a:v2.example.org a:v3.example.org -all"}},
			title: "SPF has more than two lookups that find nothing",
		},
		"loop": {
			txt:   map[string][]string{"bounce.example.com": {"v=spf1 include:bounce.example.com -all"}},
			title: "SPF record for bounce.example.com includes itself",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dns := goodDNS()
			for k, v := range tc.txt {
				dns.txt[k] = v
			}
			c := spfLookups(t, dns)
			if c.Status != verdict.Fail || c.Title != tc.title || c.Fix == nil {
				t.Errorf("spf_lookups = %s %q, want fail %q", c.Status, c.Title, tc.title)
			}
		})
	}
}

func TestSPFRedirectIgnoredWithAll(t *testing.T) {
	dns := goodDNS()
	var incl []string
	for i := 1; i <= 9; i++ {
		d := fmt.Sprintf("a%d.example.org", i)
		dns.txt[d] = []string{"v=spf1 -all"}
		incl = append(incl, "include:"+d)
	}
	dns.txt["bounce.example.com"] = []string{"v=spf1 " + strings.Join(incl, " ") + " -all redirect=r.example.org"}
	dns.txt["r.example.org"] = []string{"v=spf1 a mx -all"}
	c := spfLookups(t, dns)
	if c.Status != verdict.Warn || c.Evidence["lookups"] != 9 {
		t.Errorf("spf_lookups = %s %v, want warn at 9", c.Status, c.Evidence)
	}
}

func TestDKIMTempErrorSkipsDMARC(t *testing.T) {
	dns := tempDNS{fakeDNS: goodDNS(), fail: map[string]bool{"k1._domainkey.example.com": true}}
	env := envelope()
	env.RemoteIP = net.ParseIP("198.51.100.7")
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: env})
	wantStatus(t, v, "auth.dkim", verdict.Skipped)
	wantStatus(t, v, "auth.spf", verdict.Fail)
	wantStatus(t, v, "auth.dmarc", verdict.Skipped)
	if v.ReadyToSend {
		t.Error("ready_to_send with DMARC unknown")
	}
	for _, f := range v.TopFixes {
		if strings.Contains(f.Fix, "Set up DKIM") {
			t.Errorf("top fix %q tells them to set up DKIM they already have", f.Fix)
		}
	}
}

func TestNoDMARCRecordIsNotADMARCPass(t *testing.T) {
	dns := goodDNS()
	delete(dns.txt, "_dmarc.example.com")
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
	wantStatus(t, v, "auth.dmarc_record", verdict.Fail)
	wantStatus(t, v, "auth.dmarc", verdict.Info)
	if v.Fingerprint.Auth["dmarc"] == verdict.Pass {
		t.Error("fingerprint records a DMARC pass with no record")
	}
}

func TestBrokenSignatureDMARCDetail(t *testing.T) {
	raw := withReturnPath(buildMessage(t, msgOpts{sign: true}), "bounce@bounces.mailer.net")
	raw = bytes.Replace(raw, []byte("shooting into the sun."), []byte("shooting into the moon"), 1)
	v := analyze(t, raw, Options{})
	c := find(t, v, "auth.dmarc")
	if c.Status != verdict.Fail || !strings.Contains(c.Detail, "does not verify") || c.Fix == nil || c.Fix.Who != verdict.FixedByProvider {
		t.Errorf("dmarc = %s %q %v", c.Status, c.Detail, c.Fix)
	}
}

func TestMultipleDMARCRecords(t *testing.T) {
	dns := goodDNS()
	dns.txt["_dmarc.example.com"] = []string{"v=DMARC1; p=reject; rua=mailto:d@example.com", "v=DMARC1; p=none"}
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
	c := find(t, v, "auth.dmarc_record")
	if c.Status != verdict.Fail || !strings.HasPrefix(c.Title, "More than one DMARC record") {
		t.Errorf("dmarc_record = %s %q", c.Status, c.Title)
	}
	wantStatus(t, v, "auth.dmarc", verdict.Info)
	if v.ReadyToSend {
		t.Error("ready_to_send with no DMARC policy")
	}
}

func TestSubdomainPolicy(t *testing.T) {
	for rec, want := range map[string]string{
		"v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com": "DMARC policy is none",
		"v=DMARC1; p=none; sp=reject":                           "DMARC policy is reject",
	} {
		dns := goodDNS()
		dns.txt["_dmarc.example.com"] = []string{rec}
		dns.txt["k1._domainkey.news.example.com"] = dns.txt["k1._domainkey.example.com"]
		v := analyze(t, buildMessage(t, msgOpts{sign: true, from: "tips@news.example.com", domain: "news.example.com"}), Options{Resolver: dns})
		c := find(t, v, "auth.dmarc_record")
		if c.Status != verdict.Pass || c.Title != want || c.Evidence["policy_tag"] != "sp" {
			t.Errorf("%s: dmarc_record = %s %q %v, want %q", rec, c.Status, c.Title, c.Evidence, want)
		}
	}
}

func TestListUnsubscribeParsing(t *testing.T) {
	for h, want := range map[string][]string{
		"<https://example.com/u?l=1,2,3>":                              {"https://example.com/u?l=1,2,3"},
		"<https://example.com/u> (one click), <mailto:u@example.com>":  {"https://example.com/u", "mailto:u@example.com"},
		"(a comment with <brackets>) <https://example.com/u>":          {"https://example.com/u"},
		"<https://example.com/\r\n u>":                                 {"https://example.com/u"},
		"https://example.com/u":                                        nil,
		"<mailto:u@example.com?subject=unsubscribe>,<https://e.com/u>": {"mailto:u@example.com?subject=unsubscribe", "https://e.com/u"},
	} {
		if got := parseListURIs(h); !slices.Equal(got, want) {
			t.Errorf("parseListURIs(%q) = %q, want %q", h, got, want)
		}
	}
}

func TestListUnsubscribeWithComma(t *testing.T) {
	headers := "List-Unsubscribe: <https://example.com/u?l=1,2,3>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
	v := analyze(t, buildMessage(t, msgOpts{sign: true, headers: headers}), Options{Envelope: envelope()})
	wantStatus(t, v, "unsub.header", verdict.Pass)
	wantStatus(t, v, "unsub.one_click", verdict.Pass)
	wantStatus(t, v, "unsub.signed", verdict.Pass)
}

func TestListUnsubscribeHTTPOnly(t *testing.T) {
	headers := "List-Unsubscribe: <http://example.com/u/1>\r\n"
	v := analyze(t, buildMessage(t, msgOpts{sign: true, headers: headers}), Options{Envelope: envelope()})
	c := find(t, v, "unsub.header")
	if c.Status != verdict.Fail || c.Title != "List-Unsubscribe has an http link, not https" {
		t.Errorf("unsub.header = %s %q", c.Status, c.Title)
	}
}
