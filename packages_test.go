package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// packageVersion is the version every package and pinned CLI carries.
const packageVersion = "0.3.1"

// TestReleaseTag stops a release whose tag is not the version the packages
// pin, because they would look for a release that does not exist.
func TestReleaseTag(t *testing.T) {
	ref, ok := strings.CutPrefix(os.Getenv("GITHUB_REF"), "refs/tags/")
	if !ok {
		t.Skip("not a tag build")
	}
	if ref != "v"+packageVersion {
		t.Fatalf("tag %s, but the packages pin v%s", ref, packageVersion)
	}
}

// TestPackagePins keeps the generated pin files in step: each one is empty
// before a release, or lists both hashes of all six platforms, and they agree.
func TestPackagePins(t *testing.T) {
	hash := regexp.MustCompile(`[0-9a-f]{64}`)
	var first []string
	for i, file := range []string{
		"packages/sdk/src/hashes.ts",
		"packages/python/src/sendscore/_hashes.py",
		"packages/php/src/Hashes.php",
		"packages/rust/src/hashes.rs",
		"packages/ruby/lib/sendscore/hashes.rb",
		"packages/java/src/main/java/ai/sendscore/Hashes.java",
		"packages/dotnet/src/SendScore/Hashes.cs",
		"packages/elixir/lib/sendscore/hashes.ex",
	} {
		b, err := os.ReadFile(filepath.FromSlash(file))
		if err != nil {
			t.Fatal(err)
		}
		got := hash.FindAllString(string(b), -1)
		if len(got) != 0 && len(got) != 12 {
			t.Errorf("%s: %d hashes, want 0 or 12", file, len(got))
		}
		if i == 0 {
			first = got
		} else if !slices.Equal(got, first) {
			t.Errorf("%s disagrees with packages/sdk/src/hashes.ts", file)
		}
	}
}

// TestPackageVersions keeps every package on one version, and each one's
// pinned CLI on that same version, so a package never downloads a CLI whose
// reports it was not tested against.
func TestPackageVersions(t *testing.T) {
	want := packageVersion
	for _, c := range []struct{ file, pattern string }{
		{"packages/sdk/package.json", `"version": "([^"]+)"`},
		{"packages/sdk/package-lock.json", `"name": "sendscore",\s*"version": "([^"]+)"`},
		{"packages/sdk/src/index.ts", `ENGINE_VERSION = "([^"]+)"`},
		{"packages/python/pyproject.toml", `version = "([^"]+)"`},
		{"packages/python/src/sendscore/_binary.py", `ENGINE_VERSION = "([^"]+)"`},
		{"packages/php/src/Binary.php", `ENGINE_VERSION = '([^']+)'`},
		{"packages/rust/Cargo.toml", `version = "([^"]+)"`},
		{"packages/rust/Cargo.lock", `name = "sendscore"\nversion = "([^"]+)"`},
		{"packages/rust/src/download.rs", `ENGINE_VERSION: &str = "([^"]+)"`},
		{"packages/ruby/lib/sendscore/version.rb", `VERSION = "([^"]+)"`},
		{"packages/elixir/mix.exs", `@version "([^"]+)"`},
		{"packages/elixir/lib/sendscore/binary.ex", `@engine_version "([^"]+)"`},
		{"packages/java/pom.xml", `<artifactId>sendscore</artifactId>\s*<version>([^<]+)<`},
		{"packages/java/src/main/java/ai/sendscore/Binary.java", `ENGINE_VERSION = "([^"]+)"`},
		{"packages/dotnet/src/SendScore/SendScore.csproj", `<Version>([^<]+)<`},
		{"packages/dotnet/src/SendScore/Binary.cs", `EngineVersion = "([^"]+)"`},
	} {
		b, err := os.ReadFile(filepath.FromSlash(c.file))
		if err != nil {
			t.Error(err)
			continue
		}
		m := regexp.MustCompile(c.pattern).FindSubmatch(b)
		if m == nil {
			t.Errorf("%s: no version found", c.file)
		} else if string(m[1]) != want {
			t.Errorf("%s: version %s, want %s", c.file, m[1], want)
		}
	}
}
