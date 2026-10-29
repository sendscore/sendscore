package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sendscore/sendscore/engine"
	"github.com/sendscore/sendscore/verdict"
)

// maxMessageBytes matches what the hosted receiver accepts.
const maxMessageBytes = 25 << 20

type checkFlags struct {
	json     bool
	offline  bool
	links    bool
	ip       string
	mailFrom string
	helo     string
	tls      string
	previous string
}

func newCheck() *cobra.Command {
	f := &checkFlags{}
	c := &cobra.Command{
		Use:   "check <message.eml>",
		Short: "Check one saved email",
		Long: `Check one saved email (an .eml file, or "-" for standard input).

A saved file does not record which server delivered it, so SPF, reverse DNS,
and TLS are skipped unless you pass --ip (and ideally --mail-from). Messages
sent to a SendScore address have all of it.

Exit codes: 0 every check passed, 1 warnings only, 2 a check failed,
64 usage error.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(cmd.Context(), cmd.OutOrStdout(), args[0], f)
		},
	}
	fl := c.Flags()
	fl.BoolVar(&f.json, "json", false, "print the verdict as JSON")
	fl.BoolVar(&f.offline, "offline", false, "make no DNS lookups (checks that need DNS are skipped)")
	fl.BoolVar(&f.links, "links", false, "fetch every link and image (never unsubscribe or confirm links)")
	fl.StringVar(&f.ip, "ip", "", "IP address of the server that delivered the message")
	fl.StringVar(&f.mailFrom, "mail-from", "", "envelope sender (MAIL FROM); defaults to Return-Path")
	fl.StringVar(&f.helo, "helo", "", "HELO name the delivering server gave")
	fl.StringVar(&f.tls, "tls", "", `whether delivery used TLS: "yes" or "no"`)
	fl.StringVar(&f.previous, "previous", "", "the publication's previous issue (.eml), to list what changed")
	return c
}

func readMessage(path string) ([]byte, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		r = file
	}
	b, err := io.ReadAll(io.LimitReader(r, maxMessageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMessageBytes {
		return nil, fmt.Errorf("%s is larger than %d MB", path, maxMessageBytes>>20)
	}
	return b, nil
}

func (f *checkFlags) options() (engine.Options, error) {
	var o engine.Options
	if f.offline {
		o.Resolver = engine.OfflineResolver{}
	}
	o.CheckLinks = f.links
	if f.ip != "" {
		ip := net.ParseIP(f.ip)
		if ip == nil {
			return o, fmt.Errorf("--ip %q is not an IP address", f.ip)
		}
		o.Envelope.RemoteIP = ip
	}
	o.Envelope.MailFrom = f.mailFrom
	o.Envelope.Helo = f.helo
	switch f.tls {
	case "":
	case "yes", "true":
		t := true
		o.Envelope.TLS = &t
	case "no", "false":
		t := false
		o.Envelope.TLS = &t
	default:
		return o, fmt.Errorf(`--tls must be "yes" or "no"`)
	}
	return o, nil
}

func runCheck(ctx context.Context, out io.Writer, path string, f *checkFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	raw, err := readMessage(path)
	if err != nil {
		return err
	}
	opts, err := f.options()
	if err != nil {
		return err
	}
	if f.previous != "" {
		prevRaw, err := readMessage(f.previous)
		if err != nil {
			return err
		}
		prev, err := engine.Analyze(ctx, prevRaw, engine.Options{Resolver: opts.Resolver})
		if err != nil {
			return fmt.Errorf("%s: %w", f.previous, err)
		}
		opts.Previous = prev.Fingerprint
	}
	opts.ReceivedAt = receivedAt(raw)

	v, err := engine.Analyze(ctx, raw, opts)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if f.json {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return err
		}
	} else {
		printVerdict(out, v)
	}
	return exitFor(v)
}

// receivedAt uses the message's Date for a saved file, so a report on the
// same file is the same report tomorrow.
func receivedAt(raw []byte) time.Time {
	if d := dateHeader(raw); !d.IsZero() {
		return d.UTC()
	}
	return time.Now().UTC()
}

func exitFor(v *verdict.Verdict) error {
	switch v.Verdict {
	case verdict.Fail:
		return &ExitError{Code: ExitFail}
	case verdict.Warn:
		return &ExitError{Code: ExitWarn}
	}
	return nil
}
