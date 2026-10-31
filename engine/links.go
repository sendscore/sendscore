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
	"strconv"
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
	// linkCheckDeadline bounds all the link and image fetches of one
	// analysis together.
	linkCheckDeadline = 30 * time.Second
)

// Words in a URL that mean following it does something to a subscription.
// These are never fetched: a GET on some platforms' links is the action.
var actionWords = []string{
	"unsubscribe", "unsub", "optout", "opt-out", "opt_out", "remove",
	"confirm", "preferences", "manage", "subscription", "list-manage.com/profile",
	"disable_email",
}

// Unsubscribe words in other languages. They are matched in a URL's path
// and query only, so a host name that happens to contain one is not
// affected. Some are stems, such as "sabonn" for "desabonner" and
// "désabonner", or "sinscri" for "desinscribirse" and "désinscrire".
var actionPathWords = []string{
	"desinscri", "sinscri", "desuscri", "desabon", "sabonn", "abmeld", "abbestell", "austragen",
	"uitschrijv", "afmeld", "opzeg", "cancella", "disiscri", "annulla", "darse-de-baja", "darse_de_baja",
	"baja", "descadastr", "desinscrev", "avregistr", "avmeld", "avsluta", "odhlas", "wypisz", "rezygn",
	"abonn", "leiratkoz", "peruuta",
}

// unescapeLenient decodes the percent escapes in s that are valid and leaves
// the rest, so one bad escape cannot hide a word from the checks below.
func unescapeLenient(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isActionLink(u string, listUnsub []string) bool {
	// Twice, for a URL escaped twice over.
	l := strings.ToLower(u + " " + unescapeLenient(u) + " " + unescapeLenient(unescapeLenient(u)))
	for _, lu := range listUnsub {
		if strings.EqualFold(u, lu) || sameEndpoint(u, lu) {
			return true
		}
	}
	for _, w := range actionWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	rest := p.EscapedPath() + "?" + p.RawQuery
	rest = strings.ToLower(rest + " " + unescapeLenient(rest) + " " + unescapeLenient(unescapeLenient(rest)))
	for _, w := range actionPathWords {
		if strings.Contains(rest, w) {
			return true
		}
	}
	return false
}

// sameEndpoint reports whether link goes to the same place as an http or
// https List-Unsubscribe URI: the same host, and a path under the URI's
// own directory. Platforms put a per-recipient token in the path or query,
// so the visible link rarely matches the header exactly.
func sameEndpoint(link, listUnsub string) bool {
	lu, err := url.Parse(listUnsub)
	if err != nil || (lu.Scheme != "http" && lu.Scheme != "https") || lu.Host == "" {
		return false
	}
	l, err := url.Parse(link)
	if err != nil || !strings.EqualFold(l.Hostname(), lu.Hostname()) {
		return false
	}
	path := strings.ToLower(lu.EscapedPath())
	lp := strings.ToLower(l.EscapedPath())
	if lp == path {
		return true
	}
	dir := path[:strings.LastIndexByte(path, '/')+1]
	return dir != "" && dir != "/" && strings.HasPrefix(lp, dir)
}

// Words in a link's visible text that mean following it does something to
// a subscription. Click tracking often hides the real URL, so the text is
// the only sign.
var actionTextWords = []string{
	"unsubscribe", "unsub", "opt out", "opt-out", "optout", "preferences", "preference center",
	"manage subscription", "manage your subscription", "manage subscriptions", "subscription settings",
	"email settings", "update your profile", "confirm", "remove me", "stop receiving",
	// Other languages.
	"abbestellen", "abmelden", "austragen", "désabonner", "desabonner", "désinscri", "desinscri",
	"se désinscrire", "darse de baja", "dar de baja", "cancelar suscripción", "cancelar la suscripción",
	"anular suscripción", "uitschrijven", "afmelden", "disiscriviti", "cancella iscrizione",
	"annulla iscrizione", "annulla l'iscrizione", "descadastrar", "cancelar inscrição",
	"cancelar subscrição", "avregistrera", "avsluta prenumeration", "afmeld", "avmeld", "odhlásit",
	"wypisz", "rezygnacja", "leiratkozás", "peruuta tilaus",
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
// confirm, or preferences URL. Each call has its own transport; call
// CloseIdleConnections on the client when done with it.
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
		IdleConnTimeout:       30 * time.Second,
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

var (
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
	// globalUnicast is all of IPv6 that is allocated for the public internet.
	globalUnicast = netip.MustParsePrefix("2000::/3")
)

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
	if a.Is6() && !globalUnicast.Contains(a) {
		return false
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
	// Unknown is set when the answer says nothing about the link itself,
	// such as a timeout, a failed DNS lookup, or a refused robot.
	Unknown bool `json:"-"`
}

func (r *run) checkLinks() {
	if !r.opts.CheckLinks {
		r.add(skipped("content.links", verdict.Content, "Links not checked", "Link checking is off."))
		r.add(skipped("content.images", verdict.Content, "Images not checked", "Link checking is off."))
		return
	}
	base := r.opts.HTTPClient
	if _, offline := r.opts.Resolver.(OfflineResolver); offline && base == nil {
		// The default client resolves names itself.
		r.add(skipped("content.links", verdict.Content, "Links not checked", "Offline: fetching links needs DNS."))
		r.add(skipped("content.images", verdict.Content, "Images not checked", "Offline: fetching images needs DNS."))
		return
	}
	if base == nil {
		// One transport serves the whole analysis, and its idle
		// connections are closed when the checks are done.
		base = SafeHTTPClient()
		defer base.CloseIdleConnections()
	}
	unsub := r.listUnsubURIs()
	stops := &redirectStops{to: map[string]string{}}
	client := guardRedirects(base, unsub, stops)

	// A URL is an action link if any of its occurrences says so, whatever
	// the text of the others.
	action := map[string]bool{}
	for _, l := range r.parsed.Links {
		if isActionText(l.Text) || isActionText(l.Context) || isActionLink(l.Href, unsub) {
			action[l.Href] = true
		}
	}
	var links, skippedActions []string
	seen := map[string]bool{}
	for _, l := range r.parsed.Links {
		u := l.Href
		if seen[u] || !fetchable(u) {
			continue
		}
		seen[u] = true
		if action[u] {
			skippedActions = append(skippedActions, u)
			continue
		}
		links = append(links, u)
	}
	var images, skippedImages []string
	for _, im := range r.parsed.Images {
		if !seen[im.Src] && fetchable(im.Src) && !im.Pixel {
			seen[im.Src] = true
			if isActionLink(im.Src, unsub) {
				skippedImages = append(skippedImages, im.Src)
				continue
			}
			images = append(images, im.Src)
		}
	}

	ctx, cancel := context.WithTimeout(r.ctx, linkCheckDeadline)
	defer cancel()
	r.add(r.fetchCheck(ctx, client, stops, "content.links", "link", links, skippedActions))
	r.add(r.fetchCheck(ctx, client, stops, "content.images", "image", images, skippedImages))
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

// fetchCheck fetches the URLs and reports the broken ones. A URL still
// unfinished when ctx ends is not checked, which is not the same as broken.
func (r *run) fetchCheck(ctx context.Context, client *http.Client, stops *redirectStops, id, noun string, urls, actions []string) verdict.Check {
	truncated, total := false, len(urls)
	if len(urls) > maxLinkChecks {
		urls, truncated = urls[:maxLinkChecks], true
	}
	results := make([]linkResult, len(urls))
	unfinished := make([]bool, len(urls))
	var wg sync.WaitGroup
	sem := make(chan struct{}, linkConcurrency)
	for i, u := range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				results[i], unfinished[i] = linkResult{URL: u}, true
				return
			}
			results[i] = fetch(ctx, client, u)
			unfinished[i] = results[i].Unknown || (results[i].Error != "" && ctx.Err() != nil)
		}()
	}
	wg.Wait()

	var broken []linkResult
	var stopped []map[string]string
	var notChecked []string
	for i, res := range results {
		if unfinished[i] {
			notChecked = append(notChecked, res.URL)
			continue
		}
		if to, ok := stops.get(res.URL); ok {
			stopped = append(stopped, map[string]string{"url": res.URL, "redirects_to": to})
			continue
		}
		if res.Error != "" || res.Status >= 400 {
			broken = append(broken, res)
		}
	}
	checked := len(urls) - len(notChecked)
	ev := map[string]any{"checked": checked}
	capped(ev, "broken", broken)
	if len(notChecked) > 0 {
		capped(ev, "not_checked", notChecked)
	}
	if len(actions) > 0 {
		capped(ev, "not_followed", actions)
	}
	if len(stopped) > 0 {
		capped(ev, "redirect_not_followed", stopped)
	}
	if truncated {
		ev["truncated_at"], ev["total"] = maxLinkChecks, total
	}
	c := verdict.Check{ID: id, Category: verdict.Content, Evidence: r.noteLimit(ev)}
	switch {
	case len(urls) == 0:
		c.Status, c.Title = verdict.Info, "No "+noun+"s to check"
	case len(broken) > 0:
		c.Status, c.Title = verdict.Fail, fmt.Sprintf("%d of %d %ss are broken", len(broken), checked, noun)
		if len(notChecked) > 0 {
			c.Title = fmt.Sprintf("%d of %d checked %ss are broken", len(broken), checked, noun)
			c.Detail = fmt.Sprintf("%s could not be checked, because of a timeout, a DNS failure, a server that refuses robots, or the time for link checks running out.", plural(len(notChecked), noun))
		}
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Fix or remove the broken " + noun + "s before sending."}
	case len(notChecked) > 0:
		reason := fmt.Sprintf("%d of %d %ss gave no clear answer, because of a timeout, a DNS failure, or a server that refuses robots.", len(notChecked), len(urls), noun)
		if ctx.Err() != nil {
			reason = fmt.Sprintf("The time for link checks ran out with %d of %d %ss not checked.", len(notChecked), len(urls), noun)
		}
		if checked > 0 {
			reason += fmt.Sprintf(" The %d that were checked load.", checked)
		}
		c = skipped(id, verdict.Content, fmt.Sprintf("Not every %s could be checked", noun), reason)
		c.Evidence = r.noteLimit(ev)
	case truncated:
		c.Status, c.Title = verdict.Info, fmt.Sprintf("The first %d of %d %ss load", len(urls), total, noun)
	default:
		c = r.partial(verdict.Check{ID: id, Category: verdict.Content, Status: verdict.Pass,
			Title: fmt.Sprintf("All %d %ss load", len(urls), noun), Evidence: c.Evidence})
	}
	return c
}

// inconclusive reports whether a failed fetch says nothing about the link.
func inconclusive(err error) bool {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return !dns.IsNotFound
	}
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
		(errors.As(err, &ne) && ne.Timeout())
}

// inconclusiveStatus reports whether a status says nothing about whether the
// link works: the server is busy, or it does not answer robots.
func inconclusiveStatus(code int) bool {
	switch code {
	case 401, 403, 429, 502, 503, 504:
		return true
	}
	return false
}

func fetch(ctx context.Context, client *http.Client, u string) linkResult {
	res := linkResult{URL: u}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		req.Header.Set("User-Agent", "SendScore link check (+https://github.com/sendscore/sendscore)")
		resp, err := client.Do(req)
		if err != nil {
			res.Error, res.Unknown = err.Error(), inconclusive(err)
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		res.Status, res.Error, res.Unknown = resp.StatusCode, "", inconclusiveStatus(resp.StatusCode)
		// Many servers refuse HEAD; only a GET answer is final.
		if method == http.MethodHead && (resp.StatusCode == 405 || resp.StatusCode == 403 || resp.StatusCode == 501 || resp.StatusCode == 404 || resp.StatusCode == 429 || resp.StatusCode == 503) {
			continue
		}
		return res
	}
	return res
}
