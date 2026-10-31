package engine

import (
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

func TestCompareReportsEveryAuthChange(t *testing.T) {
	for name, tc := range map[string]struct {
		before, after verdict.Status
		listed        bool
		worse         bool
	}{
		"fixed":      {verdict.Fail, verdict.Pass, true, false},
		"worse":      {verdict.Warn, verdict.Fail, true, true},
		"regressed":  {verdict.Pass, verdict.Fail, true, true},
		"unchecked":  {verdict.Pass, verdict.Skipped, true, false},
		"recheck":    {verdict.Skipped, verdict.Fail, true, false},
		"same":       {verdict.Fail, verdict.Fail, false, false},
		"no history": {"", verdict.Fail, false, false},
	} {
		prev := &verdict.Fingerprint{Auth: map[string]verdict.Status{"dkim": tc.before}}
		cur := &verdict.Fingerprint{Auth: map[string]verdict.Status{"dkim": tc.after}}
		got := Compare(prev, cur)
		if len(got) != map[bool]int{true: 1, false: 0}[tc.listed] {
			t.Errorf("%s: changes = %+v", name, got)
			continue
		}
		if tc.listed && (got[0].Worsened != "") != tc.worse {
			t.Errorf("%s: worsened = %q", name, got[0].Worsened)
		}
	}
}
