package cmd

import (
	"bytes"
	"encoding/json"
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
		{"check", "../testdata/missing.eml"},
		{"bogus"},
	} {
		if _, code := run(t, args...); code != ExitUsage {
			t.Errorf("%v: exit = %d, want %d", args, code, ExitUsage)
		}
	}
}
