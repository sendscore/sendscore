package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sendscore/sendscore/verdict"
)

// apiMaxWait is the longest a single wait request may block on the server;
// longer waits are made of several requests.
const apiMaxWait = 50 * time.Second

// HTTPBackend reaches a SendScore app over its JSON API. It is what
// `sendscore mcp` uses, so a laptop needs no database and no mail server.
type HTTPBackend struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

func (h *HTTPBackend) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{Timeout: apiMaxWait + 15*time.Second}
}

func (h *HTTPBackend) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(h.BaseURL, "/")+path, bytes.NewReader(nil))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return fmt.Errorf("sendscore: %s", e.Error)
		}
		return fmt.Errorf("sendscore: %s answered %d", path, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

// CreateTestAddress implements Backend.
func (h *HTTPBackend) CreateTestAddress(ctx context.Context) (TestAddress, error) {
	var a TestAddress
	err := h.do(ctx, http.MethodPost, "/api/v1/test-addresses", &a)
	return a, err
}

// waitBackoff is the shortest pause between wait requests, and
// maxWaitBackoff the longest. A server that answers at once (one shutting
// down, or a proxy) is asked again after a pause that doubles each time,
// never in a tight loop.
const (
	waitBackoff    = time.Second
	maxWaitBackoff = 8 * time.Second
)

// Wait implements Backend, splitting long waits into requests the server
// accepts.
func (h *HTTPBackend) Wait(ctx context.Context, token, after string, timeout time.Duration) (*verdict.Verdict, error) {
	deadline := time.Now().Add(timeout)
	pause := waitBackoff
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, ErrNotReceived
		}
		secs := int(min(left, apiMaxWait).Seconds())
		if secs < 1 {
			secs = 1
		}
		var out struct {
			Status  string           `json:"status"`
			Verdict *verdict.Verdict `json:"verdict"`
		}
		path := "/api/v1/test-addresses/" + url.PathEscape(token) + "/wait?timeout=" + strconv.Itoa(secs)
		if after != "" {
			path += "&after=" + url.QueryEscape(after)
		}
		started := time.Now()
		if err := h.do(ctx, http.MethodGet, path, &out); err != nil {
			return nil, err
		}
		switch {
		case out.Status == "received" && out.Verdict != nil:
			return out.Verdict, nil
		case out.Status == "received":
			return nil, fmt.Errorf("sendscore: the wait answer said received but had no verdict")
		case out.Status != "not_received":
			return nil, fmt.Errorf("sendscore: the wait answer had an unknown status %q", out.Status)
		}
		// A server that held the request for most of its timeout is
		// working, so ask again soon. One that answered early gets a
		// longer pause each time.
		held := time.Since(started) >= time.Duration(secs)*time.Second/2
		if held {
			pause = waitBackoff
		}
		if err := sleep(ctx, min(pause, time.Until(deadline))); err != nil {
			return nil, err
		}
		if !held {
			pause = min(pause*2, maxWaitBackoff)
		}
	}
}

// sleep waits for d or until ctx is done.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Report implements Backend.
func (h *HTTPBackend) Report(ctx context.Context, id string) (*verdict.Verdict, error) {
	v := &verdict.Verdict{}
	err := h.do(ctx, http.MethodGet, "/api/v1/reports/"+url.PathEscape(id), v)
	return v, err
}
