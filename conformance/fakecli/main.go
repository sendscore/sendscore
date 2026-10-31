// Command fakecli stands in for the sendscore binary in the packages' tests.
// It takes its behavior from the name of the directory it runs from, because
// not every language can set a child's environment or PATH from a test.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const report = `{"schema":"sendscore.verdict/v2","new_field":{"a":1},"message":{"received_at":"","from":"","subject":"","message_id":"","size_bytes":0,"new":1},"verdict":"pass","ready_to_send":true,"summary":"","top_fixes":[],"checks":[{"id":"new.check","category":"new","status":"brand_new","title":"","new":true}],"changes":[],"explanation":null,"note":""}`

func main() {
	exe, err := os.Executable()
	if err != nil {
		os.Exit(70)
	}
	mode := filepath.Base(filepath.Dir(exe))
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		if v, ok := strings.CutPrefix(mode, "version-"); ok {
			fmt.Println("sendscore version " + v)
			return
		}
		fmt.Println("sendscore version dev")
		return
	}
	switch mode {
	case "hang":
		time.Sleep(10 * time.Minute)
	case "killed":
		p, err := os.FindProcess(os.Getpid())
		if err == nil {
			_ = p.Kill()
		}
		time.Sleep(time.Minute)
	case "planted":
		fmt.Println(`{"schema":"PLANTED"}`)
	case "noisy":
		fmt.Fprintln(os.Stderr, "a warning on stderr")
		fmt.Println(report)
		os.Exit(2)
	default:
		fmt.Println(report)
	}
}
