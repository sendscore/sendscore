package engine

import (
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

func TestUnreadableDKIMIsSkipped(t *testing.T) {
	// Headers that run to the end with no blank line.
	raw := []byte("From: T <t@example.com>\r\nDate: Tue, 28 Oct 2026 13:12:04 +0000\r\nDKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=k1; h=from; bh=x; b=y\r\n")
	v, err := Analyze(t.Context(), raw, Options{Resolver: goodDNS()})
	if err != nil {
		t.Fatal(err)
	}
	if c := checkOf(t, v, "auth.dkim"); c.Status != verdict.Skipped {
		t.Errorf("auth.dkim = %s %q", c.Status, c.Title)
	}
}
