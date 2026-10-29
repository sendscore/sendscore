package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sendscore/sendscore/verdict"
)

const (
	maxLinkChecks   = 100
	linkConcurrency = 8
	linkTimeout     = 10 * time.Second
	maxRedirects    = 5
)

// Words in a URL that mean following it does something to a subscription.
// These are never fetched: a GET on some platforms' links is the action.
var actionWords = []string{
	"unsubscribe", "unsub", "optout", "opt-out", "opt_out", "remove",
	"confirm", "preferences", "manage", "subscription", "list-manage.com/profile",
}

func isActionLink(u string, listUnsub []string) bool {
	l := strings.ToLower(u)
	for _, lu := range listUnsub {
		if strings.EqualFold(u, lu) {
			return true
		}
	}
	for _, w := range actionWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// SafeHTTPClient refuses to connect to loopback, private, and link-local
// addresses, so a message's links cannot reach the checker's own network.
func SafeHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !publicIP(ip) {
				return fmt.Errorf("refusing to connect to non-public address %s", host)
			}
			return nil
		},
	}
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: linkTimeout,
		MaxIdleConnsPerHost:   2,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   linkTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

func publicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast())
}

type linkResult struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

func (r *run) checkLinks() {
	if !r.opts.CheckLinks {
		r.add(skipped("content.links", verdict.Content, "Links not checked", "Link checking is off. Pass --links to fetch every link."))
		r.add(skipped("content.images", verdict.Content, "Images not checked", "Link checking is off. Pass --links to fetch every image."))
		return
	}
	client := r.opts.HTTPClient
	if client == nil {
		client = SafeHTTPClient()
	}
	unsub := r.listUnsubURIs()

	var links, skippedActions []string
	seen := map[string]bool{}
	for _, l := range r.parsed.Links {
		u := l.Href
		if seen[u] || !fetchable(u) {
			continue
		}
		seen[u] = true
		if isActionLink(u, unsub) {
			skippedActions = append(skippedActions, u)
			continue
		}
		links = append(links, u)
	}
	var images []string
	for _, im := range r.parsed.Images {
		if !seen[im.Src] && fetchable(im.Src) && !im.Pixel {
			seen[im.Src] = true
			images = append(images, im.Src)
		}
	}

	r.add(r.fetchCheck(client, "content.links", "link", links, skippedActions))
	r.add(r.fetchCheck(client, "content.images", "image", images, nil))
}

func fetchable(u string) bool {
	p, err := url.Parse(u)
	return err == nil && (p.Scheme == "http" || p.Scheme == "https") && p.Host != ""
}

func (r *run) fetchCheck(client *http.Client, id, noun string, urls, actions []string) verdict.Check {
	truncated := false
	if len(urls) > maxLinkChecks {
		urls, truncated = urls[:maxLinkChecks], true
	}
	results := make([]linkResult, len(urls))
	var wg sync.WaitGroup
	sem := make(chan struct{}, linkConcurrency)
	for i, u := range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = fetch(r.ctx, client, u)
		}()
	}
	wg.Wait()

	var broken []linkResult
	for _, res := range results {
		if res.Error != "" || res.Status >= 400 {
			broken = append(broken, res)
		}
	}
	ev := map[string]any{"checked": len(urls), "broken": broken}
	if len(actions) > 0 {
		ev["not_followed"] = actions
	}
	if truncated {
		ev["truncated_at"] = maxLinkChecks
	}
	c := verdict.Check{ID: id, Category: verdict.Content, Evidence: ev}
	switch {
	case len(urls) == 0:
		c.Status, c.Title = verdict.Info, "No "+noun+"s to check"
	case len(broken) == 0:
		c.Status, c.Title = verdict.Pass, fmt.Sprintf("All %d %ss load", len(urls), noun)
	default:
		c.Status, c.Title = verdict.Fail, fmt.Sprintf("%d of %d %ss are broken", len(broken), len(urls), noun)
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Fix or remove the broken " + noun + "s before sending."}
	}
	return c
}

func fetch(ctx context.Context, client *http.Client, u string) linkResult {
	res := linkResult{URL: u}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		req.Header.Set("User-Agent", "SendScore link check (+https://sendscore.ai)")
		resp, err := client.Do(req)
		if err != nil {
			res.Error = err.Error()
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		res.Status, res.Error = resp.StatusCode, ""
		// Many servers refuse HEAD; only a GET answer is final.
		if method == http.MethodHead && (resp.StatusCode == 405 || resp.StatusCode == 403 || resp.StatusCode == 501 || resp.StatusCode == 404) {
			continue
		}
		return res
	}
	return res
}
