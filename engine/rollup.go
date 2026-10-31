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
// summary from the individual checks. dnsFailed says a DNS failure hid an
// authentication result, so running the check again may help. stopped says
// the analysis was canceled or ran out of time, so some checks did not run.
func rollUp(v *verdict.Verdict, blocking []verdict.Category, dnsFailed, stopped bool) {
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
	// When DMARC or DKIM could not be evaluated, nothing shows the message
	// is authenticated as the bulk sender rules require, so it is not ready,
	// and it is never a pass.
	uncheckedID := ""
	if slices.Contains(blocking, verdict.Auth) {
		uncheckedID = authUnchecked(v.Checks)
	}
	unchecked := uncheckedID != ""
	if unchecked || stopped {
		v.ReadyToSend = false
	}
	switch {
	case fails > 0:
		v.Verdict = verdict.Fail
	case warns > 0 || unchecked || stopped:
		v.Verdict = verdict.Warn
	default:
		v.Verdict = verdict.Pass
	}

	v.TopFixes = topFixes(v.Checks, blocking)
	if unchecked && dnsFailed {
		retry := verdict.TopFix{Check: uncheckedID, Who: verdict.FixedByYou, Fix: retryAuthFix}
		v.TopFixes = append([]verdict.TopFix{retry}, v.TopFixes...)
		if len(v.TopFixes) > maxTopFixes {
			v.TopFixes = v.TopFixes[:maxTopFixes]
		}
	}
	v.Summary = summary(v, fails, warns)
	if unchecked {
		lead := authUncheckedSummary
		if !dnsFailed {
			lead = authIncompleteSummary
		}
		v.Summary = strings.TrimSpace(lead + " " + strings.TrimPrefix(v.Summary, "Every check that ran passed."))
	}
	if stopped {
		v.Summary = strings.TrimSpace(stoppedSummary + " " + strings.TrimPrefix(v.Summary, "Every check that ran passed."))
	}
}

const (
	stoppedSummary        = "The check was stopped before it finished, so this is not ready to send."
	authUncheckedSummary  = "Authentication could not be checked because DNS lookups failed, so this is not ready to send."
	authIncompleteSummary = "Authentication could not be fully checked, so this is not ready to send."
	retryAuthFix          = "Run the check again once DNS lookups work. Some authentication results could not be evaluated, which does not mean they are wrong."
)

// authUnchecked names auth.dmarc or auth.dkim when it was skipped, or
// unsub.signed when the signature that decides it could not be verified, or
// returns "".
func authUnchecked(checks []verdict.Check) string {
	for _, id := range []string{"auth.dmarc", "auth.dkim", "unsub.signed"} {
		for _, c := range checks {
			if c.ID != id || c.Status != verdict.Skipped {
				continue
			}
			if id != "unsub.signed" || c.Evidence["unverified_signature"] != nil {
				return id
			}
		}
	}
	return ""
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
