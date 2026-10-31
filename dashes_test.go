package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// generated names directories of tools' output and installed dependencies,
// here and in packages/.
var generated = map[string]bool{
	".git": true, "bin": true, "dist": true, "node_modules": true, "target": true, "vendor": true,
	"_build": true, "deps": true, "obj": true, "__pycache__": true, ".venv": true, ".pytest_cache": true,
}

// TestNoDashes keeps em and en dashes out of every file in the repository.
func TestNoDashes(t *testing.T) {
	banned := []string{"\u2014", "\u2013"}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if generated[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			for _, dash := range banned {
				if strings.Contains(line, dash) {
					t.Errorf("%s:%d has an em or en dash", path, i+1)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
