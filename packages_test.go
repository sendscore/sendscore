package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestPackageVersions keeps every package on one version, and each one's
// pinned CLI on that same version, so a package never downloads a CLI whose
// reports it was not tested against.
func TestPackageVersions(t *testing.T) {
	const want = "0.2.0"
	for _, c := range []struct{ file, pattern string }{
		{"packages/sdk/package.json", `"version": "([^"]+)"`},
		{"packages/sdk/src/index.ts", `ENGINE_VERSION = "([^"]+)"`},
		{"packages/python/pyproject.toml", `version = "([^"]+)"`},
		{"packages/python/src/sendscore/_binary.py", `ENGINE_VERSION = "([^"]+)"`},
		{"packages/php/src/Binary.php", `ENGINE_VERSION = '([^']+)'`},
		{"packages/rust/Cargo.toml", `version = "([^"]+)"`},
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
