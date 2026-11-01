// Command buildpackages turns a release into the npm packages and Python
// wheels that carry the binary, so an install needs no download. It writes
// one npm package per platform, the main npm package that depends on them,
// and one wheel per platform.
//
//	gh release download v0.3.0 --dir /tmp/release
//	(cd packages/sdk && npm ci && npm run build)
//	go run ./scripts/buildpackages -out /tmp/packages /tmp/release
//
// Every archive must match the hashes committed in the packages, and nothing
// is written if one does not. With -local it builds the binaries from this
// checkout, for tests. Those are never to be published.
package main

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/sendscore/sendscore/scripts/internal/release"
)

const hashesFile = "packages/sdk/src/hashes.ts"

type pin struct{ archive, binary string }

var pinLine = regexp.MustCompile(`(\w+_\w+):\s*\{\s*archive:\s*"([0-9a-f]{64})",\s*binary:\s*"([0-9a-f]{64})"`)

// readPins reads the hashes committed in the npm package. pinhashes writes the
// same values into all eight packages, and TestPackagePins keeps them equal.
func readPins(root string) (map[string]pin, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(hashesFile)))
	if err != nil {
		return nil, err
	}
	pins := map[string]pin{}
	for _, m := range pinLine.FindAllStringSubmatch(string(b), -1) {
		pins[m[1]] = pin{m[2], m[3]}
	}
	for _, p := range release.Platforms {
		if _, ok := pins[p]; !ok {
			return nil, fmt.Errorf("%s has no pin for %s, so run pinhashes first", hashesFile, p)
		}
	}
	return pins, nil
}

func archiveName(version, platform string) string {
	if strings.HasPrefix(platform, "windows") {
		return fmt.Sprintf("sendscore_%s_%s.zip", version, platform)
	}
	return fmt.Sprintf("sendscore_%s_%s.tar.gz", version, platform)
}

// fromRelease reads every binary from a directory of release files. Each
// archive must match its pin before it is opened, and the binary after.
func fromRelease(dir, version string, pins map[string]pin) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, p := range release.Platforms {
		name := archiveName(version, p)
		archive, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if release.Sum(archive) != pins[p].archive {
			return nil, fmt.Errorf("%s does not match its pinned hash", name)
		}
		binary, err := release.Extract(archive, name)
		if err != nil {
			return nil, err
		}
		if release.Sum(binary) != pins[p].binary {
			return nil, fmt.Errorf("the binary in %s does not match its pinned hash", name)
		}
		out[p] = binary
	}
	return out, nil
}

// fromCheckout builds every binary from the code here, with the same flags as
// a release, under the version the packages expect.
func fromCheckout(root, version string) (map[string][]byte, error) {
	tmp, err := os.MkdirTemp("", "buildpackages")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	out := map[string][]byte{}
	for _, p := range release.Platforms {
		goos, goarch, _ := strings.Cut(p, "_")
		file := filepath.Join(tmp, p)
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags",
			"-s -w -X github.com/sendscore/sendscore/cmd.version="+version, "-o", file, ".")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
		if b, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("building %s: %w\n%s", p, err, b)
		}
		if out[p], err = os.ReadFile(file); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func npmPlatform(platform string) (npmOS, cpu string) {
	goos, goarch, _ := strings.Cut(platform, "_")
	npmOS, cpu = goos, goarch
	if goos == "windows" {
		npmOS = "win32"
	}
	if goarch == "amd64" {
		cpu = "x64"
	}
	return npmOS, cpu
}

func npmName(platform string) string {
	o, c := npmPlatform(platform)
	return "@sendscore/cli-" + o + "-" + c
}

func exeName(platform string) string {
	if strings.HasPrefix(platform, "windows") {
		return "sendscore.exe"
	}
	return "sendscore"
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func repository(dir string) map[string]string {
	r := map[string]string{"type": "git", "url": "git+https://github.com/sendscore/sendscore.git"}
	if dir != "" {
		r["directory"] = dir
	}
	return r
}

// npmPlatformPackage writes one package holding one binary. It has no scripts
// and no dependencies, and npm installs it only on a matching machine.
func npmPlatformPackage(root, out, version, platform string, binary []byte) error {
	dir := filepath.Join(out, "npm", strings.TrimPrefix(npmName(platform), "@sendscore/"))
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		return err
	}
	o, c := npmPlatform(platform)
	if err := writeJSON(filepath.Join(dir, "package.json"), map[string]any{
		"name": npmName(platform), "version": version, "license": "MIT",
		"description":     "The SendScore CLI for " + o + " on " + c + ". Installed by the sendscore package.",
		"repository":      repository(""),
		"os":              []string{o},
		"cpu":             []string{c},
		"files":           []string{"bin", "README.md", "LICENSE"},
		"preferUnplugged": true,
	}); err != nil {
		return err
	}
	readme := fmt.Sprintf("# %s\n\nThe SendScore CLI for %s on %s. Install [sendscore](https://www.npmjs.com/package/sendscore), which picks this package for you.\n", npmName(platform), o, c)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(root, "LICENSE"), filepath.Join(dir, "LICENSE")); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "bin", exeName(platform)), binary, 0o755)
}

// npmMainPackage writes the package people install. The source package.json
// names no platform packages, so a checkout needs none of them to build.
func npmMainPackage(root, out, version string) error {
	src := filepath.Join(root, "packages", "sdk")
	b, err := os.ReadFile(filepath.Join(src, "package.json"))
	if err != nil {
		return err
	}
	var pkg map[string]any
	if err := json.Unmarshal(b, &pkg); err != nil {
		return err
	}
	delete(pkg, "scripts")
	delete(pkg, "devDependencies")
	optional := map[string]string{}
	for _, p := range release.Platforms {
		optional[npmName(p)] = version
	}
	pkg["optionalDependencies"] = optional
	dir := filepath.Join(out, "npm", "sendscore")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "package.json"), pkg); err != nil {
		return err
	}
	for _, f := range []string{"README.md", "LICENSE"} {
		if err := copyFile(filepath.Join(src, f), filepath.Join(dir, f)); err != nil {
			return err
		}
	}
	dist := filepath.Join(src, "dist")
	if _, err := os.Stat(filepath.Join(dist, "index.js")); err != nil {
		return errors.New("packages/sdk/dist is missing, so run npm ci and npm run build there first")
	}
	return filepath.WalkDir(dist, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dist, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dir, "dist", rel), 0o755)
		}
		return copyFile(path, filepath.Join(dir, "dist", rel))
	})
}

func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, b, 0o644)
}

// wheelTags are the platform tags of each wheel. The binary is static, so one
// file serves both manylinux and musllinux, and Go needs macOS 12 or later.
var wheelTags = map[string][]string{
	"darwin_amd64":  {"macosx_12_0_x86_64"},
	"darwin_arm64":  {"macosx_12_0_arm64"},
	"linux_amd64":   {"manylinux_2_17_x86_64", "manylinux2014_x86_64", "musllinux_1_1_x86_64"},
	"linux_arm64":   {"manylinux_2_17_aarch64", "manylinux2014_aarch64", "musllinux_1_1_aarch64"},
	"windows_amd64": {"win_amd64"},
	"windows_arm64": {"win_arm64"},
}

type wheelFile struct {
	name string
	body []byte
	mode fs.FileMode
}

func pyprojectValue(pyproject, key string) (string, error) {
	m := regexp.MustCompile(`(?m)^` + key + ` = "([^"]+)"`).FindStringSubmatch(pyproject)
	if m == nil {
		return "", fmt.Errorf("pyproject.toml has no %s", key)
	}
	return m[1], nil
}

// wheel writes one platform wheel: the Python package, plus the binary at
// sendscore/_bin, which is where the package looks for it.
func wheel(root, out, version, platform string, binary []byte) error {
	src := filepath.Join(root, "packages", "python")
	b, err := os.ReadFile(filepath.Join(src, "pyproject.toml"))
	if err != nil {
		return err
	}
	summary, err := pyprojectValue(string(b), "description")
	if err != nil {
		return err
	}
	python, err := pyprojectValue(string(b), "requires-python")
	if err != nil {
		return err
	}
	readme, err := os.ReadFile(filepath.Join(src, "README.md"))
	if err != nil {
		return err
	}
	license, err := os.ReadFile(filepath.Join(src, "LICENSE"))
	if err != nil {
		return err
	}
	var files []wheelFile
	code := filepath.Join(src, "src", "sendscore")
	entries, err := os.ReadDir(code)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".py") || e.Name() == "py.typed") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(code, e.Name()))
		if err != nil {
			return err
		}
		files = append(files, wheelFile{"sendscore/" + e.Name(), body, 0o644})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	files = append(files, wheelFile{"sendscore/_bin/" + exeName(platform), binary, 0o755})

	tags := wheelTags[platform]
	info := "sendscore-" + version + ".dist-info/"
	metadata := fmt.Sprintf("Metadata-Version: 2.1\nName: sendscore\nVersion: %s\nSummary: %s\nHome-page: https://github.com/sendscore/sendscore\nLicense: MIT\nRequires-Python: %s\nDescription-Content-Type: text/markdown\n\n%s", version, summary, python, readme)
	wheelInfo := "Wheel-Version: 1.0\nGenerator: sendscore-buildpackages\nRoot-Is-Purelib: false\n"
	for _, t := range tags {
		wheelInfo += "Tag: py3-none-" + t + "\n"
	}
	files = append(files,
		wheelFile{info + "METADATA", []byte(metadata), 0o644},
		wheelFile{info + "WHEEL", []byte(wheelInfo), 0o644},
		wheelFile{info + "entry_points.txt", []byte("[console_scripts]\nsendscore = sendscore._cli:main\n"), 0o644},
		wheelFile{info + "licenses/LICENSE", license, 0o644})

	var record strings.Builder
	for _, f := range files {
		s := sha256.Sum256(f.body)
		fmt.Fprintf(&record, "%s,sha256=%s,%d\n", f.name, base64.RawURLEncoding.EncodeToString(s[:]), len(f.body))
	}
	fmt.Fprintf(&record, "%sRECORD,,\n", info)
	files = append(files, wheelFile{info + "RECORD", []byte(record.String()), 0o644})

	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, f := range files {
		// PyPI refuses a data descriptor, which CreateHeader always writes, so
		// the sizes and checksum go in the header, ahead of the data.
		var packed bytes.Buffer
		c, err := flate.NewWriter(&packed, flate.BestCompression)
		if err != nil {
			return err
		}
		if _, err := c.Write(f.body); err != nil {
			return err
		}
		if err := c.Close(); err != nil {
			return err
		}
		h := &zip.FileHeader{
			Name:               f.name,
			Method:             zip.Deflate,
			CRC32:              crc32.ChecksumIEEE(f.body),
			CompressedSize64:   uint64(packed.Len()),
			UncompressedSize64: uint64(len(f.body)),
		}
		h.SetMode(f.mode)
		w, err := z.CreateRaw(h)
		if err != nil {
			return err
		}
		if _, err := w.Write(packed.Bytes()); err != nil {
			return err
		}
	}
	if err := z.Close(); err != nil {
		return err
	}
	dir := filepath.Join(out, "python")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	name := fmt.Sprintf("sendscore-%s-py3-none-%s.whl", version, strings.Join(tags, "."))
	return os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644)
}

// packageVersion reads the version from package.json, and refuses a
// pyproject.toml that disagrees.
func packageVersion(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "packages", "sdk", "package.json"))
	if err != nil {
		return "", err
	}
	var pkg struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		return "", err
	}
	py, err := os.ReadFile(filepath.Join(root, "packages", "python", "pyproject.toml"))
	if err != nil {
		return "", err
	}
	v, err := pyprojectValue(string(py), "version")
	if err != nil {
		return "", err
	}
	if v != pkg.Version {
		return "", fmt.Errorf("package.json says %s, and pyproject.toml says %s", pkg.Version, v)
	}
	return v, nil
}

func build(root, out, releaseDir string, local bool) error {
	version, err := packageVersion(root)
	if err != nil {
		return err
	}
	var binaries map[string][]byte
	if local {
		binaries, err = fromCheckout(root, version)
	} else {
		var pins map[string]pin
		if pins, err = readPins(root); err == nil {
			binaries, err = fromRelease(releaseDir, version, pins)
		}
	}
	if err != nil {
		return err
	}
	// Nothing older survives next to what was just built.
	if err := os.RemoveAll(out); err != nil {
		return err
	}
	if err := npmMainPackage(root, out, version); err != nil {
		return err
	}
	for _, p := range release.Platforms {
		if err := npmPlatformPackage(root, out, version, p, binaries[p]); err != nil {
			return err
		}
		if err := wheel(root, out, version, p, binaries[p]); err != nil {
			return err
		}
	}
	return nil
}

func run() error {
	out := flag.String("out", "dist/packages", "directory to write, replacing what is there")
	local := flag.Bool("local", false, "build the binaries from this checkout, for tests; never publish these")
	flag.Parse()
	if *local != (flag.NArg() == 0) || flag.NArg() > 1 {
		return errors.New("usage: buildpackages [-out dir] <directory of release files>, or buildpackages -local [-out dir]")
	}
	return build(".", *out, flag.Arg(0), *local)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "buildpackages:", err)
		os.Exit(1)
	}
}
