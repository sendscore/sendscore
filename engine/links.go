package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
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

// Words in a link's visible text that mean following it does something to
// a subscription. Click tracking often hides the real URL, so the text is
// the only sign.
var actionTextWords = []string{
	"unsubscribe", "unsub", "opt out", "opt-out", "optout", "preferences", "preference center",
	"manage subscription", "manage your subscription", "manage subscriptions", "subscription settings",
	"email settings", "update your profile", "confirm", "remove me", "stop receiving",
}

func isActionText(text string) bool {
	l := strings.ToLower(text)
	for _, w := range actionTextWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// SafeHTTPClient refuses to connect to loopback, private, link-local, and
// other non-public addresses, so a message's links cannot reach the
// checker's own network. It never follows a redirect into an unsubscribe,
// confirm, or preferences URL.
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
			if isActionLink(req.URL.String(), nil) {
				return http.ErrUseLastResponse
			}
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// Special purpose ranges that are not the public internet, from the IANA
// IPv4 and IPv6 special purpose address registries.
var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10",
		"fec0::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func publicIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	// NAT64 reaches the IPv4 address in the last four bytes.
	if nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

type linkResult struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

func (r *run) checkLinks() {
	if !r.opts.CheckLinks {
		r.add(skipped("content.links", verdict.Content, "Links not checked", "Link checking is off."))
		r.add(skipped("content.images", verdict.Content, "Images not checked", "Link checking is off."))
		return
	}
	base := r.opts.HTTPClient
	if base == nil {
		base = SafeHTTPClient()
	}
	unsub := r.listUnsubURIs()
	stops := &redirectStops{to: map[string]string{}}
	client := guardRedirects(base, unsub, stops)

	var links, skippedActions []string
	seen := map[string]bool{}
	for _, l := range r.parsed.Links {
		u := l.Href
		if seen[u] || !fetchable(u) {
			continue
		}
		seen[u] = true
		if isActionLink(u, unsub) || isActionText(l.Text) {
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

	r.add(r.fetchCheck(client, stops, "content.links", "link", links, skippedActions))
	r.add(r.fetchCheck(client, stops, "content.images", "image", images, nil))
}

// redirectStops records the redirects that were not followed because they
// lead to an unsubscribe, confirm, or preferences URL.
type redirectStops struct {
	mu sync.Mutex
	to map[string]string
}

func (s *redirectStops) get(u string) (string, bool) {
	if p, err := url.Parse(u); err == nil {
		u = p.String()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.to[u]
	return t, ok
}

// guardRedirects returns a copy of the client that stops, without
// following, at any redirect into an action URL, whatever the client's own
// redirect policy.
func guardRedirects(base *http.Client, unsub []string, stops *redirectStops) *http.Client {
	c := *base
	next := base.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if isActionLink(req.URL.String(), unsub) {
			stops.mu.Lock()
			stops.to[via[0].URL.String()] = req.URL.String()
			stops.mu.Unlock()
			return http.ErrUseLastResponse
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= maxRedirects {
			return errors.New("too many redirects")
		}
		return nil
	}
	return &c
}

func fetchable(u string) bool {
	p, err := url.Parse(u)
	return err == nil && (p.Scheme == "http" || p.Scheme == "https") && p.Host != ""
}

func (r *run) fetchCheck(client *http.Client, stops *redirectStops, id, noun string, urls, actions []string) verdict.Check {
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
	var stopped []map[string]string
	for _, res := range results {
		if to, ok := stops.get(res.URL); ok {
			stopped = append(stopped, map[string]string{"url": res.URL, "redirects_to": to})
			continue
		}
		if res.Error != "" || res.Status >= 400 {
			broken = append(broken, res)
		}
	}
	ev := map[string]any{"checked": len(urls)}
	capped(ev, "broken", broken)
	if len(actions) > 0 {
		capped(ev, "not_followed", actions)
	}
	if len(stopped) > 0 {
		capped(ev, "redirect_not_followed", stopped)
	}
	if truncated {
		ev["truncated_at"] = maxLinkChecks
	}
	c := verdict.Check{ID: id, Category: verdict.Content, Evidence: r.noteLimit(ev)}
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
