package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sendscore/sendscore/scripts/internal/release"
)

const (
	repo     = "../.."
	fixtures = repo + "/conformance/release"
	testVer  = "0.0.0-test"
)

func fixturePins(t *testing.T) map[string]pin {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]struct{ Archive, Binary string }
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	pins := map[string]pin{}
	for k, v := range raw {
		pins[k] = pin{v.Archive, v.Binary}
	}
	return pins
}

func TestReleaseArchivesMustMatchTheirPins(t *testing.T) {
	got, err := fromRelease(filepath.Join(fixtures, "good"), testVer, fixturePins(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(release.Platforms) {
		t.Errorf("read %d binaries", len(got))
	}
	if _, err := fromRelease(filepath.Join(fixtures, "altered"), testVer, fixturePins(t)); err == nil || !strings.Contains(err.Error(), "does not match its pinned hash") {
		t.Errorf("altered archive: %v", err)
	}
	wrong := fixturePins(t)
	p := wrong["linux_amd64"]
	p.binary = strings.Repeat("0", 64)
	wrong["linux_amd64"] = p
	if _, err := fromRelease(filepath.Join(fixtures, "good"), testVer, wrong); err == nil || !strings.Contains(err.Error(), "binary in") {
		t.Errorf("wrong binary: %v", err)
	}
}

// The committed file is empty between the version commit and the hashes commit,
// so this writes its own copy in the format pinhashes writes.
func TestReadPins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, filepath.FromSlash(hashesFile))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	archive, binary := strings.Repeat("a", 64), strings.Repeat("b", 64)
	body := "export const HASHES: Record<string, { archive: string; binary: string }> = {"
	for _, p := range release.Platforms {
		body += fmt.Sprintf("\n  %s: { archive: %q, binary: %q },", p, archive, binary)
	}
	write(body + "\n};\n")
	pins, err := readPins(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range release.Platforms {
		if pins[p].archive != archive || pins[p].binary != binary {
			t.Errorf("%s: %+v", p, pins[p])
		}
	}
	write("export const HASHES = {};\n")
	if _, err := readPins(dir); err == nil {
		t.Error("empty pins were accepted")
	}
}

func TestPlatformPackages(t *testing.T) {
	for platform, want := range map[string]string{
		"darwin_amd64":  "@sendscore/cli-darwin-x64",
		"darwin_arm64":  "@sendscore/cli-darwin-arm64",
		"linux_amd64":   "@sendscore/cli-linux-x64",
		"linux_arm64":   "@sendscore/cli-linux-arm64",
		"windows_amd64": "@sendscore/cli-win32-x64",
		"windows_arm64": "@sendscore/cli-win32-arm64",
	} {
		if got := npmName(platform); got != want {
			t.Errorf("%s: %s", platform, got)
		}
		if len(wheelTags[platform]) == 0 {
			t.Errorf("%s has no wheel tags", platform)
		}
	}
	out := t.TempDir()
	if err := npmPlatformPackage(repo, out, "1.2.3", "windows_arm64", []byte("MZ")); err != nil {
		t.Fatal(err)
	}
	var pkg map[string]any
	b, err := os.ReadFile(filepath.Join(out, "npm", "cli-win32-arm64", "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		t.Fatal(err)
	}
	if pkg["name"] != "@sendscore/cli-win32-arm64" || pkg["version"] != "1.2.3" || pkg["scripts"] != nil {
		t.Errorf("package.json: %v", pkg)
	}
	if fmt.Sprint(pkg["os"], pkg["cpu"]) != "[win32] [arm64]" {
		t.Errorf("os and cpu: %v %v", pkg["os"], pkg["cpu"])
	}
	if _, err := os.Stat(filepath.Join(out, "npm", "cli-win32-arm64", "bin", "sendscore.exe")); err != nil {
		t.Error(err)
	}
}

func TestMainNpmPackageHasNoScripts(t *testing.T) {
	dist := filepath.Join(repo, "packages", "sdk", "dist", "index.js")
	if _, err := os.Stat(dist); err != nil {
		t.Skip("packages/sdk is not built")
	}
	out := t.TempDir()
	if err := npmMainPackage(repo, out, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var pkg struct {
		Scripts  map[string]any    `json:"scripts"`
		Dev      map[string]any    `json:"devDependencies"`
		Optional map[string]string `json:"optionalDependencies"`
	}
	b, err := os.ReadFile(filepath.Join(out, "npm", "sendscore", "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		t.Fatal(err)
	}
	if pkg.Scripts != nil || pkg.Dev != nil {
		t.Errorf("scripts %v, devDependencies %v", pkg.Scripts, pkg.Dev)
	}
	if len(pkg.Optional) != len(release.Platforms) || pkg.Optional["@sendscore/cli-linux-x64"] != "1.2.3" {
		t.Errorf("optionalDependencies: %v", pkg.Optional)
	}
}

func TestWheel(t *testing.T) {
	out := t.TempDir()
	if err := wheel(repo, out, "1.2.3", "linux_arm64", []byte("binary")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(out, "python", "sendscore-1.2.3-py3-none-manylinux_2_17_aarch64.manylinux2014_aarch64.musllinux_1_1_aarch64.whl")
	z, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	files := map[string]string{}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = string(b)
		if f.Name == "sendscore/_bin/sendscore" && f.Mode().Perm() != 0o755 {
			t.Errorf("binary mode %v", f.Mode())
		}
	}
	if !strings.Contains(files["sendscore-1.2.3.dist-info/entry_points.txt"], "sendscore = sendscore._cli:main") {
		t.Errorf("the wheel has no sendscore command: %v", files)
	}
	if files["sendscore/_bin/sendscore"] != "binary" || files["sendscore/__init__.py"] == "" {
		t.Error("the wheel is missing the binary or the code")
	}
	info := "sendscore-1.2.3.dist-info/"
	for _, want := range []string{"Name: sendscore", "Version: 1.2.3", "Requires-Python: >=3.10"} {
		if !strings.Contains(files[info+"METADATA"], want) {
			t.Errorf("METADATA has no %q", want)
		}
	}
	if !strings.Contains(files[info+"WHEEL"], "Root-Is-Purelib: false\nTag: py3-none-manylinux_2_17_aarch64\n") {
		t.Errorf("WHEEL:\n%s", files[info+"WHEEL"])
	}
	// RECORD lists every file with its real hash, and leaves its own blank.
	for _, line := range strings.Split(strings.TrimSpace(files[info+"RECORD"]), "\n") {
		parts := strings.Split(line, ",")
		if parts[0] == info+"RECORD" {
			continue
		}
		s := sha256.Sum256([]byte(files[parts[0]]))
		if parts[1] != "sha256="+base64.RawURLEncoding.EncodeToString(s[:]) {
			t.Errorf("RECORD is wrong for %s", parts[0])
		}
	}
}

// PyPI refuses a wheel with a data descriptor, which is bit 3 of the general
// purpose flags in each local file header.
func TestWheelHasNoDataDescriptors(t *testing.T) {
	out := t.TempDir()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("binary "), 4096)
	if err := wheel(root, out, "0.0.0", "linux_amd64", body); err != nil {
		t.Fatal(err)
	}
	names, err := filepath.Glob(filepath.Join(out, "python", "*.whl"))
	if err != nil || len(names) != 1 {
		t.Fatalf("wheels = %v, %v", names, err)
	}
	raw, err := os.ReadFile(names[0])
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range z.File {
		if f.Flags&0x8 != 0 {
			t.Errorf("%s has a data descriptor in the central directory", f.Name)
		}
		off, err := f.DataOffset()
		if err != nil {
			t.Fatal(err)
		}
		// The local header sits before the data: signature, version, flags.
		nameLen := int64(len(f.Name))
		start := off - 30 - nameLen - int64(len(f.Extra))
		if start < 0 || !bytes.Equal(raw[start:start+4], []byte("PK\x03\x04")) {
			continue
		}
		if raw[start+6]&0x8 != 0 {
			t.Errorf("%s has a data descriptor in its local header", f.Name)
		}
	}
	if bytes.Contains(raw, []byte("PK\x07\x08")) {
		t.Error("the wheel holds a data descriptor signature")
	}
}
