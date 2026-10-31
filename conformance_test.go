package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the expected fields in conformance/cases.json")

// conformanceCase is one entry in conformance/cases.json. The packages read
// the same file, so its fields are part of what they are tested against.
type conformanceCase struct {
	Name        string            `json:"name"`
	Command     string            `json:"command"`
	Message     string            `json:"message,omitempty"`
	Via         string            `json:"via,omitempty"`
	Before      string            `json:"before,omitempty"`
	After       string            `json:"after,omitempty"`
	Options     map[string]any    `json:"options,omitempty"`
	Exit        int               `json:"exit"`
	Verdict     string            `json:"verdict,omitempty"`
	ReadyToSend *bool             `json:"ready_to_send,omitempty"`
	Checks      map[string]string `json:"checks,omitempty"`
	Changes     []string          `json:"changes,omitempty"`
	Worsened    []string          `json:"worsened,omitempty"`
}

type conformanceFile struct {
	Description string            `json:"description"`
	Cases       []conformanceCase `json:"cases"`
}

func runConformance(t *testing.T, bin string, c conformanceCase) conformanceCase {
	t.Helper()
	got := conformanceCase{Name: c.Name, Command: c.Command, Message: c.Message, Via: c.Via, Before: c.Before, After: c.After, Options: c.Options}
	var args []string
	var stdin []byte
	if c.Command == "diff" {
		args = []string{"diff", "--json", c.Before, c.After}
	} else {
		args = []string{"check", "--json", "--offline"}
		for _, o := range []struct{ key, flag string }{{"ip", "--ip"}, {"mail_from", "--mail-from"}, {"helo", "--helo"}, {"previous", "--previous"}} {
			if v, ok := c.Options[o.key].(string); ok {
				args = append(args, o.flag, v)
			}
		}
		if links, _ := c.Options["links"].(bool); links {
			args = append(args, "--links")
		}
		if tls, ok := c.Options["tls"].(bool); ok {
			args = append(args, "--tls", map[bool]string{true: "yes", false: "no"}[tls])
		}
		if c.Via == "stdin" {
			b, err := os.ReadFile(filepath.Join("conformance", c.Message))
			if err != nil {
				t.Fatal(err)
			}
			stdin = b
			args = append(args, "-")
		} else {
			args = append(args, c.Message)
		}
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = "conformance"
	cmd.Stdin = bytes.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		got.Exit = exit.ExitCode()
	}
	if got.Exit > 2 {
		return got
	}
	var report struct {
		Verdict     string `json:"verdict"`
		ReadyToSend *bool  `json:"ready_to_send"`
		Checks      []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"checks"`
		Changes []struct {
			Field    string `json:"field"`
			Worsened string `json:"worsened"`
		} `json:"changes"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	got.Verdict, got.ReadyToSend = report.Verdict, report.ReadyToSend
	if len(report.Checks) > 0 {
		got.Checks = map[string]string{}
	}
	for _, c := range report.Checks {
		got.Checks[c.ID] = c.Status
	}
	for _, c := range report.Changes {
		got.Changes = append(got.Changes, c.Field)
		if c.Worsened != "" {
			got.Worsened = append(got.Worsened, c.Worsened)
		}
	}
	return got
}

func TestConformance(t *testing.T) {
	path := filepath.Join("conformance", "cases.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f conformanceFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "sendscore")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for i, c := range f.Cases {
		got := runConformance(t, bin, c)
		if *update {
			f.Cases[i] = got
			continue
		}
		want, _ := json.Marshal(c)
		have, _ := json.Marshal(got)
		if !bytes.Equal(want, have) {
			t.Errorf("%s:\n want %s\n have %s", c.Name, want, have)
		}
	}
	if *update {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(f); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
