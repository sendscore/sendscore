package engine

import (
	"net"
	"strings"
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

func TestSPFErrorPastTheMatchIsAWarning(t *testing.T) {
	dns := goodDNS()
	dns.txt["bounce.example.com"] = []string{"v=spf1 ip4:203.0.113.0/24 include:gone.example -all"}
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: envelope()})
	c := checkOf(t, v, "auth.spf_lookups")
	if c.Status != verdict.Warn || strings.Contains(c.Detail, "every message") {
		t.Errorf("auth.spf_lookups = %s %q", c.Status, c.Detail)
	}
	if !v.ReadyToSend {
		t.Error("a passing message is not ready")
	}
	if _, ok := checkOf(t, v, "auth.spf").Evidence["error"]; ok {
		t.Errorf("a pass carries an error: %v", checkOf(t, v, "auth.spf").Evidence)
	}

	// When SPF does not pass, the error is a failure as before.
	env := envelope()
	env.RemoteIP = net.ParseIP("198.51.100.9")
	v = analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: dns, Envelope: env})
	if c := checkOf(t, v, "auth.spf_lookups"); c.Status != verdict.Fail {
		t.Errorf("auth.spf_lookups = %s", c.Status)
	}
}
