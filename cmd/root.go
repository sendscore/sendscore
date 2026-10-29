// Package cmd is the sendscore command line.
package cmd

import (
	"errors"
	"fmt"
	"io"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is set with -ldflags at release time.
var version = "dev"

// Exit codes. A script can tell "warnings only" from "something failed".
const (
	ExitOK    = 0
	ExitWarn  = 1
	ExitFail  = 2
	ExitUsage = 64
)

// ExitError carries an exit code out of a command.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "sendscore",
		Short: "Check a newsletter email before, and after, it goes out",
		Long: `SendScore checks a received email: SPF, DKIM, DMARC and alignment,
one-click unsubscribe, structure, merge tags, and links. It can compare an
issue with the previous one.

It reports what the message proves. It never claims inbox placement.`,
		Version:       resolveVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newCheck(), newDiff())
	return root
}

// Execute runs the command line.
func Execute() error {
	return newRoot().Execute()
}

// ExitCode turns the error from Execute into the process exit code.
func ExitCode(err error, stderr io.Writer) int {
	if err == nil {
		return ExitOK
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		if exitErr.Err != nil {
			fmt.Fprintln(stderr, exitErr.Err)
		}
		return exitErr.Code
	}
	fmt.Fprintf(stderr, "Error: %v\nRun 'sendscore --help' for usage.\n", err)
	return ExitUsage
}

func resolveVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}
