package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

func run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	root := newRoot()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	code := ExitCode(root.Execute(), &errOut)
	return out.String() + errOut.String(), code
}

func TestCheckJSON(t *testing.T) {
	out, code := run(t, "check", "--offline", "--json", "../testdata/sample.eml")
	if code != ExitFail {
		t.Errorf("exit = %d, want %d\n%s", code, ExitFail, out)
	}
	var v verdict.Verdict
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if v.Schema != verdict.Schema || v.Message.Subject != "Shooting into the sun" {
		t.Errorf("verdict = %+v", v)
	}
	if got := v.Message.ReceivedAt.Format("2006-01-02"); got != "2026-10-28" {
		t.Errorf("received_at = %s, want the Date header", got)
	}
}

func TestCheckText(t *testing.T) {
	out, _ := run(t, "check", "--offline", "../testdata/sample.eml")
	for _, want := range []string{"Authentication", "No one-click unsubscribe", "Unrendered merge tags", "Fix first", "Ready to send: no"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestDiffSameFile(t *testing.T) {
	out, code := run(t, "diff", "--offline", "../testdata/sample.eml", "../testdata/sample.eml")
	if code != ExitOK || !strings.Contains(out, "nothing changed") {
		t.Errorf("exit = %d\n%s", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"check"},
		{"check", "--ip", "nope", "../testdata/sample.eml"},
		{"check", "--tls", "maybe", "../testdata/sample.eml"},
		{"bogus"},
		{"diff", "../testdata/sample.eml"},
	} {
		if _, code := run(t, args...); code != ExitUsage {
			t.Errorf("%v: exit = %d, want %d", args, code, ExitUsage)
		}
	}
}

func TestInputErrors(t *testing.T) {
	junk := filepath.Join(t.TempDir(), "junk.eml")
	if err := os.WriteFile(junk, []byte(" not a header\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"check", "../testdata/missing.eml"}, ExitNoInput},
		{[]string{"check", "--previous", "../testdata/missing.eml", "../testdata/sample.eml"}, ExitNoInput},
		{[]string{"diff", "../testdata/sample.eml", "../testdata/missing.eml"}, ExitNoInput},
		{[]string{"check", "--offline", junk}, ExitDataErr},
		{[]string{"diff", junk, "../testdata/sample.eml"}, ExitDataErr},
	} {
		out, code := run(t, tc.args...)
		if code != tc.want {
			t.Errorf("%v: exit = %d, want %d\n%s", tc.args, code, tc.want, out)
		}
		if strings.Contains(out, "for usage") {
			t.Errorf("%v: an input error suggested a usage problem:\n%s", tc.args, out)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestOutputErrors(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		err := runCheck(context.Background(), failingWriter{}, "../testdata/sample.eml", &checkFlags{offline: true, json: asJSON})
		if code := ExitCode(err, &bytes.Buffer{}); code != ExitIOErr {
			t.Errorf("json=%v: exit = %d, want %d", asJSON, code, ExitIOErr)
		}
	}
	err := runDiff(context.Background(), failingWriter{}, "../testdata/sample.eml", "../testdata/sample.eml", false)
	if code := ExitCode(err, &bytes.Buffer{}); code != ExitIOErr {
		t.Errorf("diff: exit = %d, want %d", code, ExitIOErr)
	}
}

func TestHelpHidesSecrets(t *testing.T) {
	t.Setenv("SENDSCORE_SPAMHAUS_DQS_KEY", "secretdqskey123")
	t.Setenv("SENDSCORE_SURBL_ZONE", "secretzone.example")
	out, _ := run(t, "check", "--help")
	if strings.Contains(out, "secretdqskey123") || strings.Contains(out, "secretzone.example") {
		t.Errorf("help shows a secret:\n%s", out)
	}
	// The environment is still used once the flags are parsed.
	o, err := (&checkFlags{}).options()
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Blocklists) != 2 {
		t.Errorf("blocklists = %d, want the two from the environment", len(o.Blocklists))
	}
}

func TestTextReportEscapesControls(t *testing.T) {
	raw, err := os.ReadFile("../testdata/sample.eml")
	if err != nil {
		t.Fatal(err)
	}
	// ESC ] 0 ; HACKED BEL ESC [ 2 J, then a forged verdict on its own line.
	evil := "Subject: =?utf-8?b?G10wO0hBQ0tFRAcbWzJKClBBU1MgIEV2ZXJ5IGNoZWNrIHBhc3NlZA==?=\n"
	lines := strings.SplitAfter(string(raw), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "Subject:") {
			lines[i] = evil
		}
	}
	path := filepath.Join(t.TempDir(), "evil.eml")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := run(t, "check", "--offline", path)
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("report contains raw control characters: %q", out)
	}
	if !strings.Contains(out, `\x1b]0;HACKED\x07\x1b[2J\x0aPASS  Every check passed`) {
		t.Errorf("report does not show the escaped subject:\n%s", out)
	}
}

func TestSafe(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":         "plain text",
		"tab\tkept":          "tab\tkept",
		"cr\rline":           `cr\x0dline`,
		"del\x7f":            `del\x7f`,
		"c1\u009b31m":        `c1\u009b31m`,
		"bidi\u202eevil":     `bidi\u202eevil`,
		"bad utf8 \xff here": "bad utf8 \uFFFD here",
	} {
		if got := safe(in); got != want {
			t.Errorf("safe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDiffIgnoresAuthentication(t *testing.T) {
	fp, err := messageFingerprint(context.Background(), "../testdata/sample.eml")
	if err != nil {
		t.Fatal(err)
	}
	if fp.Auth != nil {
		t.Errorf("auth = %v, want none compared", fp.Auth)
	}
	if fp.ReturnPathDomain == "" || !fp.ListUnsubscribe || len(fp.LinkHosts) == 0 {
		t.Errorf("fingerprint lost what the message carries: %+v", fp)
	}
}
