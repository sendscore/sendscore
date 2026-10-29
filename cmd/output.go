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

// errWriter keeps the first write error, so a report that could not be
// written is an error rather than a silent partial report.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	e.err = err
	return n, err
}

// safe makes a string from the message, DNS, or a server safe to print on
// a terminal. Control characters (ANSI and OSC escapes, carriage returns,
// and newlines among them), C1 controls, and bidirectional overrides are
// shown as escapes instead of being sent to the terminal. Tabs are kept.
func safe(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	clean := true
	for _, r := range s {
		if unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case !unsafeRune(r):
			b.WriteRune(r)
		case r < 0x80:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	switch {
	case r == '\t':
		return false
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x2028, r == 0x2029, r == 0x200e, r == 0x200f, r == 0x061c:
		return true
	}
	return false
}

func printVerdict(out io.Writer, v *verdict.Verdict) error {
	w := &errWriter{w: out}
	fmt.Fprintf(w, "%s%s%s\n", colorBold, safe(v.Message.Subject), colorReset)
	fmt.Fprintf(w, "%sfrom %s%s\n\n", colorGray, safe(v.Message.From), colorReset)

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
			fmt.Fprintf(w, "  %s  %s\n", mark(c.Status), safe(c.Title))
			if c.Status == verdict.Fail || c.Status == verdict.Warn {
				if c.Detail != "" {
					fmt.Fprintf(w, "        %s%s%s\n", colorGray, safe(c.Detail), colorReset)
				}
			}
			if c.Status == verdict.Skipped && c.Reason != "" {
				fmt.Fprintf(w, "        %s%s%s\n", colorGray, safe(c.Reason), colorReset)
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
			fmt.Fprintf(w, "  %d. %s %s(%s, %s)%s\n", i+1, safe(f.Fix), colorGray, who, safe(f.Check), colorReset)
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
	fmt.Fprintf(w, "%s  %s\n", verdictWord, safe(v.Summary))
	fmt.Fprintf(w, "Ready to send: %s\n", ready)
	fmt.Fprintf(w, "%s%s%s\n", colorGray, safe(v.Note), colorReset)
	return w.err
}

func printChanges(out io.Writer, changes []verdict.Change) error {
	w, ok := out.(*errWriter)
	if !ok {
		w = &errWriter{w: out}
	}
	fmt.Fprintf(w, "%sChanges since the previous issue%s\n", colorBold, colorReset)
	if len(changes) == 0 {
		fmt.Fprintf(w, "  %snothing changed%s\n\n", colorGray, colorReset)
		return w.err
	}
	for _, c := range changes {
		flag := "    "
		if c.Worsened != "" {
			flag = colorYellow + "worse" + colorReset
		}
		fmt.Fprintf(w, "  %s %s: %v %s->%s %v\n", flag, safe(c.Field), show(c.Before), colorGray, colorReset, show(c.After))
	}
	fmt.Fprintln(w)
	return w.err
}

func show(v any) string {
	switch x := v.(type) {
	case []string:
		if len(x) == 0 {
			return "(none)"
		}
		return safe(strings.Join(x, ", "))
	case string:
		if x == "" {
			return "(none)"
		}
		return safe(x)
	}
	return safe(fmt.Sprint(v))
}
