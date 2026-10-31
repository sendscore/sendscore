// Package engine checks one received email and returns a verdict. Every
// check is deterministic: the same message, envelope, and DNS answers give the
// same verdict. Nothing here guesses at a mailbox provider's filtering.
package engine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/sendscore/sendscore/verdict"
)

// Resolver is the DNS the engine uses. *net.Resolver satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Envelope is what the receiving SMTP server saw, which the message itself
// cannot prove. A saved .eml file has none of it, so the checks that need it
// are skipped unless it is supplied.
type Envelope struct {
	RemoteIP net.IP
	Helo     string
	MailFrom string
	// TLS is nil when unknown.
	TLS *bool
}

// Options configures one analysis.
type Options struct {
	Envelope Envelope
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// CheckLinks fetches every link and image. Off by default: it is slow,
	// and it touches the publisher's tracking links.
	CheckLinks bool
	// HTTPClient is used for link checks. It defaults to a client that
	// refuses private and loopback addresses.
	HTTPClient *http.Client
	// Previous is the fingerprint of the publication's last issue. When set,
	// the verdict lists what changed.
	Previous *verdict.Fingerprint
	// ReceivedAt defaults to now.
	ReceivedAt time.Time
	// Blocking lists the categories whose failures make ready_to_send
	// false. Nil means authentication and unsubscribe.
	Blocking []verdict.Category
	// Blocklists are the domain blocklists content.blocklists looks link
	// domains up on. Empty means the check is skipped.
	Blocklists []Blocklist
}

// ErrOffline is what an offline resolver returns. Checks that see it are
// skipped rather than failed.
var ErrOffline = errors.New("offline: DNS lookups are disabled")

// OfflineResolver answers every lookup with ErrOffline.
type OfflineResolver struct{}

func (OfflineResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, ErrOffline }
func (OfflineResolver) LookupMX(context.Context, string) ([]*net.MX, error) { return nil, ErrOffline }
func (OfflineResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, ErrOffline
}
func (OfflineResolver) LookupAddr(context.Context, string) ([]string, error) { return nil, ErrOffline }

// run carries one analysis through the checks.
type run struct {
	ctx    context.Context
	opts   Options
	res    Resolver
	msg    *message
	checks []verdict.Check
	fp     verdict.Fingerprint

	// Shared between checks.
	dkim    []dkimResult
	fromDom string
	spfDom  string
	spfRes  verdict.Status
	// spfTemp is set when SPF was skipped because DNS failed.
	spfTemp bool
	// authDNS is set when a DNS failure hid an authentication result.
	authDNS  bool
	parsed   *parsedHTML
	dmarcRec *dmarcRecord
	dmarcErr error
	// multiFrom is set when the message has more than one From address.
	multiFrom bool
}

// A hostile name server can stall each of the many lookups authentication
// makes, so each has a timeout and all of them together have a deadline. They
// are variables so tests need not wait.
var (
	lookupTimeout = 5 * time.Second
	authDeadline  = 20 * time.Second
)

// timedResolver gives each lookup its own timeout.
type timedResolver struct{ Resolver }

func (t timedResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	return t.Resolver.LookupTXT(ctx, name)
}

func (t timedResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	return t.Resolver.LookupMX(ctx, name)
}

func (t timedResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	return t.Resolver.LookupIPAddr(ctx, host)
}

func (t timedResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	return t.Resolver.LookupAddr(ctx, addr)
}

// Analyze checks one raw RFC 5322 message.
func Analyze(ctx context.Context, raw []byte, opts Options) (*verdict.Verdict, error) {
	msg, err := parseMessage(raw)
	if err != nil {
		return nil, err
	}
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.ReceivedAt.IsZero() {
		opts.ReceivedAt = time.Now().UTC()
	}
	r := &run{ctx: ctx, opts: opts, res: timedResolver{opts.Resolver}, msg: msg}
	r.fp.Auth = map[string]verdict.Status{}
	r.fromDom = addrDomain(msg.Header.Get("From"))
	r.multiFrom = msg.fromCount() > 1

	r.structure()
	authCtx, cancelAuth := context.WithTimeout(ctx, authDeadline)
	r.ctx = authCtx
	r.auth()
	r.ctx = ctx
	cancelAuth()
	r.unsubscribe()
	r.content()

	v := &verdict.Verdict{
		Schema: verdict.Schema,
		Message: verdict.Message{
			ReceivedAt: opts.ReceivedAt,
			From:       msg.get("From"),
			Subject:    msg.get("Subject"),
			MessageID:  msg.Header.Get("Message-Id"),
			SizeBytes:  len(raw),
		},
		Checks:      r.checks,
		Changes:     []verdict.Change{},
		Fingerprint: &r.fp,
		Note:        verdict.Note,
	}
	if opts.Previous != nil {
		v.Changes = Compare(opts.Previous, &r.fp)
		if c, ok := regressionCheck(v.Changes); ok {
			v.Checks = append(v.Checks, c)
		}
	}
	rollUp(v, opts.Blocking, r.authDNS, ctx.Err() != nil)
	return v, nil
}

func (r *run) add(c verdict.Check) {
	r.checks = append(r.checks, c)
}

func skipped(id string, cat verdict.Category, title, reason string) verdict.Check {
	return verdict.Check{ID: id, Category: cat, Status: verdict.Skipped, Title: title, Reason: reason}
}

// lookupFailed turns a DNS error into a skip reason, or "" when the error
// means the name simply does not exist.
func lookupFailed(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrOffline) {
		return "Offline: DNS lookups are disabled."
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return ""
	}
	return "DNS lookup failed: " + err.Error()
}
