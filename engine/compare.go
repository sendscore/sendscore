package engine

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sendscore/sendscore/verdict"
)

// sizeJump is how much the HTML may grow between issues before it is called
// out.
const sizeJump = 0.25

// Compare lists what changed from prev to cur. A change is plain information
// unless it made a check worse, in which case Worsened names that check.
func Compare(prev, cur *verdict.Fingerprint) []verdict.Change {
	out := []verdict.Change{}
	add := func(field string, before, after any, worsened string) {
		out = append(out, verdict.Change{Field: field, Before: before, After: after, Worsened: worsened})
	}
	listChanged := func(a, b []string) bool {
		a, b = slices.Clone(a), slices.Clone(b)
		slices.Sort(a)
		slices.Sort(b)
		return !slices.Equal(a, b)
	}

	for _, name := range []string{"dkim", "spf", "dmarc"} {
		before, after := prev.Auth[name], cur.Auth[name]
		if before == verdict.Pass && after != verdict.Pass && after != verdict.Skipped && after != "" {
			add("auth."+name, before, after, "auth."+name)
		}
	}
	if listChanged(prev.DKIMDomains, cur.DKIMDomains) {
		add("dkim.d", strings.Join(prev.DKIMDomains, ", "), strings.Join(cur.DKIMDomains, ", "), "")
	}
	if listChanged(prev.DKIMSelectors, cur.DKIMSelectors) {
		add("dkim.selector", strings.Join(prev.DKIMSelectors, ", "), strings.Join(cur.DKIMSelectors, ", "), "")
	}
	if prev.ReturnPathDomain != cur.ReturnPathDomain {
		add("return_path.domain", prev.ReturnPathDomain, cur.ReturnPathDomain, "")
	}
	if prev.RemoteIP != "" && cur.RemoteIP != "" && prev.RemoteIP != cur.RemoteIP {
		add("sending.ip", prev.RemoteIP, cur.RemoteIP, "")
	}
	if prev.PTR != "" && cur.PTR != "" && prev.PTR != cur.PTR {
		add("sending.ptr", prev.PTR, cur.PTR, "")
	}
	if prev.ListUnsubscribe != cur.ListUnsubscribe {
		w := ""
		if !cur.ListUnsubscribe {
			w = "unsub.header"
		}
		add("unsub.list_unsubscribe", prev.ListUnsubscribe, cur.ListUnsubscribe, w)
	}
	if prev.OneClick != cur.OneClick {
		w := ""
		if !cur.OneClick {
			w = "unsub.one_click"
		}
		add("unsub.one_click", prev.OneClick, cur.OneClick, w)
	}
	if listChanged(prev.LinkHosts, cur.LinkHosts) {
		var gone, added []string
		for _, h := range prev.LinkHosts {
			if !slices.Contains(cur.LinkHosts, h) {
				gone = append(gone, h)
			}
		}
		for _, h := range cur.LinkHosts {
			if !slices.Contains(prev.LinkHosts, h) {
				added = append(added, h)
			}
		}
		add("links.hosts", gone, added, "")
	}
	if prev.HTMLBytes > 0 && float64(cur.HTMLBytes) > float64(prev.HTMLBytes)*(1+sizeJump) {
		w := ""
		if cur.HTMLBytes > clipWarnBytes {
			w = "struct.html_size"
		}
		add("html.bytes", prev.HTMLBytes, cur.HTMLBytes, w)
	}
	if prev.Links != cur.Links {
		add("links.count", prev.Links, cur.Links, "")
	}
	if prev.Images != cur.Images {
		add("images.count", prev.Images, cur.Images, "")
	}
	return out
}

// regressionCheck turns the changes that made something worse into one
// warning, so they reach top_fixes and the overall verdict.
func regressionCheck(changes []verdict.Change) (verdict.Check, bool) {
	var worse []string
	for _, c := range changes {
		if c.Worsened != "" {
			worse = append(worse, fmt.Sprintf("%s (%v to %v)", c.Field, c.Before, c.After))
		}
	}
	if len(worse) == 0 {
		return verdict.Check{}, false
	}
	return verdict.Check{
		ID: "changes.regressions", Category: verdict.Changes, Status: verdict.Warn,
		Title:    "Worse than the previous issue: " + strings.Join(worse, "; "),
		Evidence: map[string]any{"changes": worse},
		Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Something changed since the last issue. Check recent template, DNS, or platform changes."},
	}, true
}
