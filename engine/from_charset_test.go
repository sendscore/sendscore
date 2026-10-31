package engine

import (
	"strings"
	"testing"

	"github.com/sendscore/sendscore/verdict"
)

func TestEncodedDisplayNamesAreValidFrom(t *testing.T) {
	for _, name := range []string{"=?windows-1252?Q?Jos=E9?=", "=?iso-2022-jp?B?GyRCJCIbKEI=?=", "=?gb2312?B?1tDOxA==?="} {
		raw := []byte(strings.Replace(plainHeaders, "From: T <", "From: "+name+" <", 1) + "Content-Type: text/plain\r\n\r\nhello unsubscribe\r\n")
		v := analyze(t, raw, Options{Resolver: goodDNS()})
		if c := checkOf(t, v, "struct.headers"); c.Status != verdict.Pass {
			t.Errorf("%s: struct.headers = %s %q", name, c.Status, c.Title)
		}
	}
}
