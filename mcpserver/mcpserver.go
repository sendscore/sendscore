// Package mcpserver defines SendScore's MCP tools. The same tools are served
// two ways: by the hosted app as a remote connector (over its own database),
// and by `sendscore mcp` on a laptop (over the hosted API, see HTTPBackend).
// Everything of substance lives here so the two never drift apart.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sendscore/sendscore/engine"
	"github.com/sendscore/sendscore/verdict"
)

// TestAddress is a one-time address that checks whatever is sent to it.
type TestAddress struct {
	Address   string    `json:"address"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	PageURL   string    `json:"page_url,omitempty"`
}

// Backend is where the tools get their data.
type Backend interface {
	CreateTestAddress(ctx context.Context) (TestAddress, error)
	// Wait blocks up to timeout for a message at the address. With after
	// set to a report ID from the same address, only a message received
	// after that report counts; without it, the newest message does, even
	// one that arrived before the call. It returns ErrNotReceived when none
	// arrived in time.
	Wait(ctx context.Context, token, after string, timeout time.Duration) (*verdict.Verdict, error)
	Report(ctx context.Context, id string) (*verdict.Verdict, error)
}

// ErrNotReceived means no message reached the address before the timeout.
var ErrNotReceived = errors.New("not received")

// ErrNotFound means the address or report does not exist or has expired.
var ErrNotFound = errors.New("not found")

const (
	// One wait is capped at 50 seconds, below the 60 second idle timeouts
	// of common proxies such as nginx and AWS load balancers; agents call
	// again to keep waiting.
	defaultWait = 45 * time.Second
	maxWait     = 50 * time.Second
)

// New builds the MCP server over a backend.
func New(b Backend, version string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "sendscore", Title: "SendScore", Version: version}, &mcp.ServerOptions{
		Instructions: "SendScore checks a newsletter email before it goes out. Call get_test_address, " +
			"send a preview of the issue to that address from the email platform, then call wait_for_message. " +
			"The verdict says whether the issue is ready to send and lists at most three fixes, each marked as " +
			"fixed by the publisher (you) or the email platform (provider). Checks are deterministic. " +
			"Receipt at SendScore is not inbox placement: never tell the user an issue will reach the inbox.",
	})
	t := &tools{b: b}

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_test_address",
		Title:       "Get a test address",
		Description: "Create a one-time email address. Send a preview of the newsletter issue to it from the email platform, then call wait_for_message with the token. The address accepts mail for 24 hours. To check a fixed version, send it to the same address and pass the earlier report_id to wait_for_message as after_report_id.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false)},
	}, t.getTestAddress)

	mcp.AddTool(s, &mcp.Tool{
		Name:  "wait_for_message",
		Title: "Wait for the test email",
		Description: "Wait until the preview arrives at a test address, then return its verdict: verdict (pass, warn, or fail), ready_to_send, summary, top_fixes, and report_id. " +
			"Without after_report_id it returns the newest message at the address, even one that arrived before the call. " +
			"When sending again to the same address (for example after a fix), pass the previous report_id as after_report_id so only a newer message counts. " +
			"Waits up to 50 seconds per call. Returns status not_received if nothing arrived in time; call again to keep waiting.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)},
	}, t.waitForMessage)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_report",
		Title:       "Get a full report",
		Description: "Return the full verdict for a report: every check with its status, evidence, and fix, plus the fingerprint used for comparisons.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)},
	}, t.getReport)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "compare_to_previous",
		Title:       "Compare with the previous issue",
		Description: "List what changed between two reports, for example last week's issue and today's preview: signing domains, Return-Path, unsubscribe headers, link hosts, size, and authentication results. Changes that made a check worse are marked worsened.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)},
	}, t.compareToPrevious)
	return s
}

type tools struct{ b Backend }

type empty struct{}

func (t *tools) getTestAddress(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, TestAddress, error) {
	a, err := t.b.CreateTestAddress(ctx)
	return nil, a, err
}

type waitIn struct {
	Token          string `json:"token" jsonschema:"the token returned by get_test_address"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"how long to wait, up to 50 seconds (default 45)"`
	AfterReportID  string `json:"after_report_id,omitempty" jsonschema:"a report_id from an earlier send to this address; only a message received after it is returned"`
}

// WaitOut is the short form of a verdict an agent acts on.
type WaitOut struct {
	Status      string           `json:"status"`
	ReportID    string           `json:"report_id,omitempty"`
	Subject     string           `json:"subject,omitempty"`
	Verdict     verdict.Status   `json:"verdict,omitempty"`
	ReadyToSend bool             `json:"ready_to_send"`
	Summary     string           `json:"summary,omitempty"`
	TopFixes    []verdict.TopFix `json:"top_fixes,omitempty"`
	Note        string           `json:"note,omitempty"`
}

func (t *tools) waitForMessage(ctx context.Context, _ *mcp.CallToolRequest, in waitIn) (*mcp.CallToolResult, WaitOut, error) {
	if in.Token == "" {
		return nil, WaitOut{}, errors.New("token is required")
	}
	timeout := defaultWait
	if in.TimeoutSeconds > 0 {
		timeout = min(time.Duration(in.TimeoutSeconds)*time.Second, maxWait)
	}
	v, err := t.b.Wait(ctx, in.Token, in.AfterReportID, timeout)
	if errors.Is(err, ErrNotReceived) {
		return nil, WaitOut{Status: "not_received", Note: "Nothing has arrived yet. Check the preview was sent to the exact address, then call wait_for_message again."}, nil
	}
	if err != nil {
		return nil, WaitOut{}, err
	}
	return nil, WaitOut{
		Status: "received", ReportID: v.ID, Subject: v.Message.Subject, Verdict: v.Verdict,
		ReadyToSend: v.ReadyToSend, Summary: v.Summary, TopFixes: v.TopFixes, Note: v.Note,
	}, nil
}

type reportIn struct {
	ReportID string `json:"report_id" jsonschema:"the report_id from wait_for_message"`
}

func (t *tools) getReport(ctx context.Context, _ *mcp.CallToolRequest, in reportIn) (*mcp.CallToolResult, any, error) {
	if in.ReportID == "" {
		return nil, nil, errors.New("report_id is required")
	}
	v, err := t.b.Report(ctx, in.ReportID)
	if err != nil {
		return nil, nil, err
	}
	return nil, v, nil
}

type compareIn struct {
	ReportID         string `json:"report_id" jsonschema:"the newer report, usually today's preview"`
	PreviousReportID string `json:"previous_report_id" jsonschema:"the older report to compare against"`
}

type compareOut struct {
	ReportID         string           `json:"report_id"`
	PreviousReportID string           `json:"previous_report_id"`
	Changes          []verdict.Change `json:"changes"`
}

func (t *tools) compareToPrevious(ctx context.Context, _ *mcp.CallToolRequest, in compareIn) (*mcp.CallToolResult, any, error) {
	if in.ReportID == "" || in.PreviousReportID == "" {
		return nil, nil, errors.New("report_id and previous_report_id are required")
	}
	cur, err := t.b.Report(ctx, in.ReportID)
	if err != nil {
		return nil, nil, fmt.Errorf("report %s: %w", in.ReportID, err)
	}
	prev, err := t.b.Report(ctx, in.PreviousReportID)
	if err != nil {
		return nil, nil, fmt.Errorf("report %s: %w", in.PreviousReportID, err)
	}
	if cur.Fingerprint == nil || prev.Fingerprint == nil {
		return nil, nil, errors.New("one of the reports has no fingerprint to compare")
	}
	return nil, compareOut{
		ReportID: in.ReportID, PreviousReportID: in.PreviousReportID,
		Changes: engine.Compare(prev.Fingerprint, cur.Fingerprint),
	}, nil
}

func ptr[T any](v T) *T { return &v }
