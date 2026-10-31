package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

func TestUnverifiedUnsubSignatureIsNotReady(t *testing.T) {
	k2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k2.PublicKey)
	base := []byte(plainHeaders + "Content-Type: text/plain\r\n\r\nhello unsubscribe\r\n")
	raw := signWith(t, base, "example.com", "k1", testKey, []string{"From", "Subject", "List-Unsubscribe", "List-Unsubscribe-Post"})
	raw = signWith(t, raw, "esp.example", "k2", k2, []string{"From", "Subject"})
	dns := goodDNS()
	dns.txt["k2._domainkey.esp.example"] = []string{"v=DKIM1; p=" + base64.StdEncoding.EncodeToString(der)}
	v := analyze(t, raw, Options{Resolver: failKey{dns, "k1._domainkey.example.com"}, Envelope: envelope()})
	if v.ReadyToSend || v.Verdict == verdict.Pass {
		t.Errorf("ready = %v, verdict %s", v.ReadyToSend, v.Verdict)
	}

	// With no header at all, the missing header says why, not the signature.
	noHeader := []byte(strings.Replace(strings.Replace(plainHeaders, "List-Unsubscribe: <https://example.com/unsub/x>\r\n", "", 1),
		"List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n", "", 1) + "Content-Type: text/plain\r\n\r\nhello\r\n")
	v = analyze(t, noHeader, Options{Resolver: goodDNS(), Envelope: envelope()})
	if strings.Contains(v.Summary, "could not be fully checked") {
		t.Errorf("summary = %q", v.Summary)
	}
}
