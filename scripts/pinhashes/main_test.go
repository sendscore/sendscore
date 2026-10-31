package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const release = "../../conformance/release"

func TestFixturePinsAreCurrent(t *testing.T) {
	got, err := read(filepath.Join(release, "good"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(release, "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]pin
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pins.json is stale: run the command in conformance/release/README.md")
	}
}

func TestChangedArchiveIsRefused(t *testing.T) {
	dir := t.TempDir()
	entries, err := os.ReadDir(filepath.Join(release, "good"))
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range entries {
		b, err := os.ReadFile(filepath.Join(release, "good", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			b = append(b, 0)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := read(dir); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("err = %v", err)
	}
}

func TestRenderedPinsHoldEveryHash(t *testing.T) {
	pins, err := read(filepath.Join(release, "good"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		text := render(target, pins)
		for key, p := range pins {
			for _, want := range []string{key, p.Archive, p.Binary} {
				if !strings.Contains(text, want) {
					t.Errorf("%s has no %s", target.path, want)
				}
			}
		}
	}
}
