package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sendscore/sendscore/verdict"
)

var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

func init() {
	if !useColor() {
		colorReset, colorRed, colorGreen, colorYellow, colorGray, colorBold = "", "", "", "", "", ""
	}
}

// useColor honours NO_COLOR and turns colour off when stdout is not a
// terminal.
func useColor() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

var categoryNames = []struct {
	cat  verdict.Category
	name string
}{
	{verdict.Auth, "Authentication"},
	{verdict.Unsub, "Unsubscribe"},
	{verdict.Structure, "Structure"},
	{verdict.Content, "Content"},
	{verdict.Delivery, "Delivery"},
	{verdict.Changes, "Changes"},
}

func mark(s verdict.Status) string {
	switch s {
	case verdict.Pass:
		return colorGreen + "pass" + colorReset
	case verdict.Warn:
		return colorYellow + "warn" + colorReset
	case verdict.Fail:
		return colorRed + "fail" + colorReset
	case verdict.Skipped:
		return colorGray + "skip" + colorReset
	}
	return colorGray + "info" + colorReset
}

func printVerdict(w io.Writer, v *verdict.Verdict) {
	fmt.Fprintf(w, "%s%s%s\n", colorBold, v.Message.Subject, colorReset)
	fmt.Fprintf(w, "%sfrom %s%s\n\n", colorGray, v.Message.From, colorReset)

	for _, cn := range categoryNames {
		var rows []verdict.Check
		for _, c := range v.Checks {
			if c.Category == cn.cat {
				rows = append(rows, c)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s%s%s\n", colorBold, cn.name, colorReset)
		for _, c := range rows {
			fmt.Fprintf(w, "  %s  %s\n", mark(c.Status), c.Title)
			if c.Status == verdict.Fail || c.Status == verdict.Warn {
				if c.Detail != "" {
					fmt.Fprintf(w, "        %s%s%s\n", colorGray, c.Detail, colorReset)
				}
			}
			if c.Status == verdict.Skipped && c.Reason != "" {
				fmt.Fprintf(w, "        %s%s%s\n", colorGray, c.Reason, colorReset)
			}
		}
		fmt.Fprintln(w)
	}

	if len(v.Changes) > 0 {
		printChanges(w, v.Changes)
	}

	if len(v.TopFixes) > 0 {
		fmt.Fprintf(w, "%sFix first%s\n", colorBold, colorReset)
		for i, f := range v.TopFixes {
			who := "you"
			if f.Who == verdict.FixedByProvider {
				who = "your email platform"
			}
			fmt.Fprintf(w, "  %d. %s %s(%s, %s)%s\n", i+1, f.Fix, colorGray, who, f.Check, colorReset)
		}
		fmt.Fprintln(w)
	}

	verdictWord := strings.ToUpper(string(v.Verdict))
	switch v.Verdict {
	case verdict.Pass:
		verdictWord = colorGreen + verdictWord + colorReset
	case verdict.Warn:
		verdictWord = colorYellow + verdictWord + colorReset
	case verdict.Fail:
		verdictWord = colorRed + verdictWord + colorReset
	}
	ready := "yes"
	if !v.ReadyToSend {
		ready = "no"
	}
	fmt.Fprintf(w, "%s  %s\n", verdictWord, v.Summary)
	fmt.Fprintf(w, "Ready to send: %s\n", ready)
	fmt.Fprintf(w, "%s%s%s\n", colorGray, v.Note, colorReset)
}

func printChanges(w io.Writer, changes []verdict.Change) {
	fmt.Fprintf(w, "%sChanges since the previous issue%s\n", colorBold, colorReset)
	if len(changes) == 0 {
		fmt.Fprintf(w, "  %snothing changed%s\n\n", colorGray, colorReset)
		return
	}
	for _, c := range changes {
		flag := "    "
		if c.Worsened != "" {
			flag = colorYellow + "worse" + colorReset
		}
		fmt.Fprintf(w, "  %s %s: %v %s->%s %v\n", flag, c.Field, show(c.Before), colorGray, colorReset, show(c.After))
	}
	fmt.Fprintln(w)
}

func show(v any) string {
	switch x := v.(type) {
	case []string:
		if len(x) == 0 {
			return "(none)"
		}
		return strings.Join(x, ", ")
	case string:
		if x == "" {
			return "(none)"
		}
		return x
	}
	return fmt.Sprint(v)
}
