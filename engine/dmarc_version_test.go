package engine

import (
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

func TestDMARCVersionTag(t *testing.T) {
	for rec, want := range map[string]bool{
		"v=DMARC1; p=reject":   true,
		"v = DMARC1; p=reject": true,
		"v=DMARC1":             true,
		"V=DMARC1; p=none":     true,
		"v=DMARC10; p=reject":  false,
		"v=DMARC2; p=reject":   false,
		"p=reject; v=DMARC1":   false,
		"spf":                  false,
	} {
		if got := isDMARCRecord(rec); got != want {
			t.Errorf("%q: %v", rec, got)
		}
	}
	dns := goodDNS()
	dns.txt["_dmarc.example.com"] = []string{"v = DMARC1; p=reject"}
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
	if c := checkOf(t, v, "auth.dmarc_record"); c.Status == verdict.Fail {
		t.Errorf("spaced record = %s %q", c.Status, c.Title)
	}
}
