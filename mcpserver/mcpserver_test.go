package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sendscore/sendscore/engine"
	"github.com/sendscore/sendscore/verdict"
)

func sampleVerdict(t *testing.T, id string, mutate func([]byte) []byte) *verdict.Verdict {
	t.Helper()
	raw, err := os.ReadFile("../testdata/sample.eml")
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		raw = mutate(raw)
	}
	v, err := engine.Analyze(context.Background(), raw, engine.Options{Resolver: engine.OfflineResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	v.ID = id
	return v
}

// fakeAPI serves the app's JSON API from memory.
func fakeAPI(t *testing.T, reports map[string]*verdict.Verdict, arriveAfter int32) (*httptest.Server, *atomic.Int32) {
	waits := &atomic.Int32{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/test-addresses", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, `{"error":"missing token"}`, http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"address": "t-abc@in.test", "token": "abc", "expires_at": time.Now().Add(time.Hour)})
	})
	mux.HandleFunc("GET /api/v1/test-addresses/{token}/wait", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("token") != "abc" {
			http.Error(w, `{"error":"no such test address"}`, http.StatusNotFound)
			return
		}
		if waits.Add(1) <= arriveAfter {
			json.NewEncoder(w).Encode(map[string]any{"status": "not_received"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "received", "report_id": "rpt_new", "verdict": reports["rpt_new"]})
	})
	mux.HandleFunc("GET /api/v1/reports/{id}", func(w http.ResponseWriter, r *http.Request) {
		v, ok := reports[r.PathValue("id")]
		if !ok {
			http.Error(w, `{"error":"no such report"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(v)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, waits
}

func connect(t *testing.T, b Backend) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := New(b, "test").Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any, out any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if out != nil && !res.IsError {
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s structured content: %v", name, err)
		}
	}
	return res
}

func TestToolsOverHTTPBackend(t *testing.T) {
	reports := map[string]*verdict.Verdict{
		"rpt_old": sampleVerdict(t, "rpt_old", nil),
		"rpt_new": sampleVerdict(t, "rpt_new", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), "List-Unsubscribe: <https://example.com/unsubscribe?u=1>\n", "", 1))
		}),
	}
	srv, waits := fakeAPI(t, reports, 1)
	cs := connect(t, &HTTPBackend{BaseURL: srv.URL, Token: "tok"})

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "compare_to_previous,get_report,get_test_address,wait_for_message" {
		t.Errorf("tools = %v", names)
	}

	var addr TestAddress
	call(t, cs, "get_test_address", map[string]any{}, &addr)
	if addr.Address != "t-abc@in.test" || addr.Token != "abc" {
		t.Errorf("address = %+v", addr)
	}

	// The first poll finds nothing; the backend keeps polling inside the timeout.
	var got WaitOut
	call(t, cs, "wait_for_message", map[string]any{"token": "abc", "timeout_seconds": 5}, &got)
	if got.Status != "received" || got.ReportID != "rpt_new" || got.ReadyToSend || len(got.TopFixes) == 0 {
		t.Errorf("wait = %+v", got)
	}
	if waits.Load() != 2 {
		t.Errorf("wait polls = %d, want 2", waits.Load())
	}

	var full verdict.Verdict
	call(t, cs, "get_report", map[string]any{"report_id": "rpt_new"}, &full)
	if full.Schema != verdict.Schema || len(full.Checks) == 0 {
		t.Errorf("report = %+v", full)
	}

	var cmp compareOut
	call(t, cs, "compare_to_previous", map[string]any{"report_id": "rpt_new", "previous_report_id": "rpt_old"}, &cmp)
	found := false
	for _, c := range cmp.Changes {
		if c.Field == "unsub.list_unsubscribe" && c.Worsened == "unsub.header" {
			found = true
		}
	}
	if !found {
		t.Errorf("changes = %+v, want the removed List-Unsubscribe", cmp.Changes)
	}

	if res := call(t, cs, "get_report", map[string]any{"report_id": "rpt_missing"}, nil); !res.IsError {
		t.Error("missing report was not an error")
	}
}

func TestWaitTimesOutQuietly(t *testing.T) {
	srv, _ := fakeAPI(t, map[string]*verdict.Verdict{}, 1000)
	cs := connect(t, &HTTPBackend{BaseURL: srv.URL, Token: "tok"})
	var got WaitOut
	call(t, cs, "wait_for_message", map[string]any{"token": "abc", "timeout_seconds": 1}, &got)
	if got.Status != "not_received" {
		t.Errorf("wait = %+v", got)
	}
}
