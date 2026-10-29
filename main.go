package main

import (
	"os"

	"github.com/sendscore/sendscore/cmd"
)

func main() {
	os.Exit(cmd.ExitCode(cmd.Execute(), os.Stderr))
}
