// Package release reads the archives of a SendScore release.
package release

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Platforms lists every release target, as os_arch.
var Platforms = []string{"darwin_amd64", "darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64", "windows_arm64"}

// Sum is the hex SHA-256 of b.
func Sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Extract returns the binary inside a release archive, by its exact name, so
// no path in the archive is ever used.
func Extract(archive []byte, name string) ([]byte, error) {
	exe := "sendscore"
	if strings.HasSuffix(name, ".zip") {
		z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, err
		}
		for _, f := range z.File {
			if f.Name == exe+".exe" {
				r, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer r.Close()
				return io.ReadAll(r)
			}
		}
		return nil, fmt.Errorf("%s has no binary", name)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	t := tar.NewReader(gz)
	for {
		h, err := t.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s has no binary", name)
		}
		if err != nil {
			return nil, err
		}
		if h.Name == exe && h.Typeflag == tar.TypeReg {
			return io.ReadAll(t)
		}
	}
}
