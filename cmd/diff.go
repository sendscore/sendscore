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
		Long: `Compare two saved emails: before and after a platform migration, a
template edit, or a DNS change. Lists changes in signing domains, the
Return-Path, unsubscribe headers, link hosts, size, and authentication.

Exits 1 when a change made a check worse, 0 otherwise.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd.Context(), cmd.OutOrStdout(), args[0], args[1], asJSON, offline)
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print the changes as JSON")
	c.Flags().BoolVar(&offline, "offline", false, "make no DNS lookups")
	return c
}

func runDiff(ctx context.Context, out io.Writer, before, after string, asJSON, offline bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var opts engine.Options
	if offline {
		opts.Resolver = engine.OfflineResolver{}
	}
	var fps [2]*verdict.Fingerprint
	for i, p := range []string{before, after} {
		raw, err := readMessage(p)
		if err != nil {
			return err
		}
		v, err := engine.Analyze(ctx, raw, opts)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		fps[i] = v.Fingerprint
	}
	changes := engine.Compare(fps[0], fps[1])

	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"before": before, "after": after, "changes": changes}); err != nil {
			return err
		}
	} else {
		printChanges(out, changes)
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
	return d
}
