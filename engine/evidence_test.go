package engine

import (
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

func TestEveryCheckThatRanHasEvidence(t *testing.T) {
	v := analyze(t, buildMessage(t, msgOpts{sign: true}), Options{Resolver: goodDNS(), Envelope: envelope()})
	for _, c := range v.Checks {
		if c.Status != verdict.Skipped && len(c.Evidence) == 0 {
			t.Errorf("%s (%s) has no evidence", c.ID, c.Status)
		}
	}
}
