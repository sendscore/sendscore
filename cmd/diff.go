package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"time"

	"github.com/spf13/cobra"

	"github.com/sendscore/sendscore/engine"
	"github.com/sendscore/sendscore/verdict"
)

func newDiff() *cobra.Command {
	var asJSON, offline bool
	c := &cobra.Command{
		Use:   "diff <before.eml> <after.eml>",
		Short: "Show what changed between two issues",
		Long: `Compare two saved emails, for example before and after a platform
migration or a template edit. Lists changes in signing domains and
selectors, the Return-Path, unsubscribe headers, link hosts, the number of
links and images, and size.

Only what the messages themselves carry is compared, and no DNS lookups are
made. Authentication results are not compared, because re-checking an older
message against today's DNS would not show what it got when it was sent. To
see whether a DNS change broke authentication, run sendscore check on a new
message.

Exits 1 when a change made a check worse, and 0 otherwise. The other exit
codes are 64 usage error, 65 an input is not an email message, 66 an input
cannot be read, 70 internal error, and 74 the report cannot be written.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd.Context(), cmd.OutOrStdout(), args[0], args[1], asJSON)
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print the changes as JSON")
	// diff never looks anything up, so --offline is kept only so old
	// scripts keep working.
	c.Flags().BoolVar(&offline, "offline", false, "make no DNS lookups (always the case)")
	_ = c.Flags().MarkHidden("offline")
	return c
}

// messageFingerprint analyzes a saved message without DNS and keeps only the
// facts the message itself carries. Authentication results are dropped:
// checked today, an older message would get today's answer, not its own.
func messageFingerprint(ctx context.Context, path string) (*verdict.Fingerprint, error) {
	raw, err := readMessage(path)
	if err != nil {
		return nil, err
	}
	v, err := engine.Analyze(ctx, raw, engine.Options{Resolver: engine.OfflineResolver{}, ReceivedAt: receivedAt(raw)})
	if err != nil {
		return nil, withCode(ExitDataErr, fmt.Errorf("%s: %w", path, err))
	}
	fp := v.Fingerprint
	if fp == nil {
		return nil, withCode(ExitSoftware, fmt.Errorf("%s: the engine returned no fingerprint", path))
	}
	fp.Auth = nil
	return fp, nil
}

func runDiff(ctx context.Context, out io.Writer, before, after string, asJSON bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var fps [2]*verdict.Fingerprint
	for i, p := range []string{before, after} {
		fp, err := messageFingerprint(ctx, p)
		if err != nil {
			return err
		}
		fps[i] = fp
	}
	changes := engine.Compare(fps[0], fps[1])

	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"before": before, "after": after, "changes": changes}); err != nil {
			return withCode(ExitIOErr, err)
		}
	} else if err := printChanges(out, changes); err != nil {
		return withCode(ExitIOErr, err)
	}
	for _, c := range changes {
		if c.Worsened != "" {
			return &ExitError{Code: ExitWarn}
		}
	}
	return nil
}

func dateHeader(raw []byte) time.Time {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return time.Time{}
	}
	d, err := m.Header.Date()
	if err != nil {
		return time.Time{}
	}
	// JSON can hold only these years, and a time zone can move a date out.
	if y := d.UTC().Year(); y < 1 || y > 9999 {
		return time.Time{}
	}
	return d
}
