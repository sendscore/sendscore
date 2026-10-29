package engine

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sendscore/sendscore/verdict"
)

const maxTopFixes = 3

var defaultBlocking = []verdict.Category{verdict.Auth, verdict.Unsub}

// rollUp sets the overall verdict, ready_to_send, the top fixes, and the
// summary from the individual checks.
func rollUp(v *verdict.Verdict, blocking []verdict.Category) {
	if blocking == nil {
		blocking = defaultBlocking
	}
	fails, warns := 0, 0
	v.ReadyToSend = true
	for _, c := range v.Checks {
		switch c.Status {
		case verdict.Fail:
			fails++
			if slices.Contains(blocking, c.Category) {
				v.ReadyToSend = false
			}
		case verdict.Warn:
			warns++
		}
	}
	// When DMARC could not be evaluated, nothing shows the message is
	// authenticated, so it is not ready, and it is never a pass.
	unchecked := slices.Contains(blocking, verdict.Auth) && authUnchecked(v.Checks)
	if unchecked {
		v.ReadyToSend = false
	}
	switch {
	case fails > 0:
		v.Verdict = verdict.Fail
	case warns > 0 || unchecked:
		v.Verdict = verdict.Warn
	default:
		v.Verdict = verdict.Pass
	}

	v.TopFixes = topFixes(v.Checks, blocking)
	if unchecked {
		retry := verdict.TopFix{Check: "auth.dmarc", Who: verdict.FixedByYou, Fix: retryAuthFix}
		v.TopFixes = append([]verdict.TopFix{retry}, v.TopFixes...)
		if len(v.TopFixes) > maxTopFixes {
			v.TopFixes = v.TopFixes[:maxTopFixes]
		}
	}
	v.Summary = summary(v, fails, warns)
	if unchecked {
		v.Summary = strings.TrimSpace(authUncheckedSummary + " " + strings.TrimPrefix(v.Summary, "Every check that ran passed."))
	}
}

const (
	authUncheckedSummary = "Authentication could not be checked, so this is not ready to send."
	retryAuthFix         = "Run the check again once DNS lookups work. DKIM, SPF, and DMARC could not be evaluated, which does not mean they are wrong."
)

// authUnchecked is true when auth.dmarc was skipped.
func authUnchecked(checks []verdict.Check) bool {
	for _, c := range checks {
		if c.ID == "auth.dmarc" && c.Status == verdict.Skipped {
			return true
		}
	}
	return false
}

// topFixes orders blocking failures first, then other failures, then
// warnings, and drops a fix whose text repeats one already chosen.
func topFixes(checks []verdict.Check, blocking []verdict.Category) []verdict.TopFix {
	rank := func(c verdict.Check) int {
		switch {
		case c.Status == verdict.Fail && slices.Contains(blocking, c.Category):
			return 0
		case c.Status == verdict.Fail:
			return 1
		case c.Status == verdict.Warn:
			return 2
		}
		return 3
	}
	var cands []verdict.Check
	for _, c := range checks {
		if c.Fix != nil && rank(c) < 3 {
			cands = append(cands, c)
		}
	}
	slices.SortStableFunc(cands, func(a, b verdict.Check) int { return rank(a) - rank(b) })

	out := []verdict.TopFix{}
	seen := map[string]bool{}
	for _, c := range cands {
		if seen[c.Fix.Text] {
			continue
		}
		seen[c.Fix.Text] = true
		out = append(out, verdict.TopFix{Check: c.ID, Who: c.Fix.Who, Fix: c.Fix.Text})
		if len(out) == maxTopFixes {
			break
		}
	}
	return out
}

func summary(v *verdict.Verdict, fails, warns int) string {
	if fails == 0 && warns == 0 {
		return "Every check that ran passed."
	}
	var titles []string
	for _, c := range v.Checks {
		if c.Status == verdict.Fail && len(titles) < 2 {
			titles = append(titles, c.Title)
		}
	}
	if len(titles) == 0 {
		for _, c := range v.Checks {
			if c.Status == verdict.Warn && len(titles) < 2 {
				titles = append(titles, c.Title)
			}
		}
	}
	counts := []string{}
	if fails > 0 {
		counts = append(counts, plural(fails, "failure"))
	}
	if warns > 0 {
		counts = append(counts, plural(warns, "warning"))
	}
	return fmt.Sprintf("%s. %s.", strings.Join(counts, " and "), strings.Join(titles, "; "))
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
