package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"

	"github.com/sendscore/sendscore/verdict"
)

const (
	docsGmail   = "https://support.google.com/mail/answer/81126"
	docsSPF     = "https://www.rfc-editor.org/rfc/rfc7208"
	docsDMARC   = "https://www.rfc-editor.org/rfc/rfc7489"
	docsRFC8058 = "https://www.rfc-editor.org/rfc/rfc8058"
)

const dkimBrokenFix = "Ask your email platform why its DKIM signature fails. Something is changing the message after signing, or the published key does not match."

type dkimResult struct {
	Domain     string
	Selector   string
	Algorithm  string
	Result     string // pass, fail, temperror, permerror
	Error      string
	HeaderKeys []string
	KeyType    string
	KeyBits    int
	Aligned    bool
	// ExpiredAfterReceipt is a signature whose x= has passed now but had not
	// when the message was received, so it can no longer be verified.
	ExpiredAfterReceipt bool
}

func (d dkimResult) evidence() map[string]any {
	e := map[string]any{
		"d": d.Domain, "s": d.Selector, "a": d.Algorithm,
		"result": d.Result, "aligned": d.Aligned,
	}
	if d.KeyBits > 0 {
		e["key_bits"] = d.KeyBits
	}
	if d.KeyType != "" {
		e["key_type"] = d.KeyType
	}
	if d.Error != "" {
		e["error"] = d.Error
	}
	if d.ExpiredAfterReceipt {
		e["expired_after_receipt"] = true
	}
	return e
}

type dmarcRecord struct {
	Domain string
	Raw    string
	Rec    *dmarc.Record
	// Records lists every record when there is more than one.
	Records []string
	// ParseErr is set when the record has a syntax error but its policy
	// could still be read, as RFC 7489 section 6.3 tells receivers to do.
	ParseErr error
}

// tolerantDMARC reads the tags that decide the outcome from a record that
// does not parse, and leaves the rest at their defaults. It returns nil when
// the policy itself is unusable.
func tolerantDMARC(raw string) *dmarc.Record {
	rec := &dmarc.Record{DKIMAlignment: dmarc.AlignmentRelaxed, SPFAlignment: dmarc.AlignmentRelaxed}
	policy := func(v string) dmarc.Policy {
		switch p := dmarc.Policy(strings.ToLower(v)); p {
		case dmarc.PolicyNone, dmarc.PolicyQuarantine, dmarc.PolicyReject:
			return p
		}
		return ""
	}
	align := func(v string) dmarc.AlignmentMode {
		if strings.EqualFold(v, "s") {
			return dmarc.AlignmentStrict
		}
		return dmarc.AlignmentRelaxed
	}
	for _, part := range strings.Split(raw, ";") {
		k, v, _ := strings.Cut(part, "=")
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "p":
			rec.Policy = policy(v)
		case "sp":
			rec.SubdomainPolicy = policy(v)
		case "adkim":
			rec.DKIMAlignment = align(v)
		case "aspf":
			rec.SPFAlignment = align(v)
		}
	}
	if rec.Policy == "" {
		return nil
	}
	return rec
}

func (r *run) auth() {
	r.verifyDKIM()
	r.checkSPF()
	r.checkSPFLookups()
	r.checkDMARCRecord()
	r.checkDMARC()
	r.checkAlignment()
	r.checkPTR()
	r.checkTLS()
}

func (r *run) lookupTXT(name string) ([]string, error) {
	return r.res.LookupTXT(r.ctx, name)
}

// dkimLookupTXT marks every failed key lookup temporary. go-msgauth calls
// any lookup error that is not a temporary net.Error a missing key, so a
// canceled, timed out, or refused query would read as a broken signature.
func (r *run) dkimLookupTXT(name string) ([]string, error) {
	txts, err := r.lookupTXT(name)
	if lookupFailed(err) != "" {
		return nil, tempLookupError{err}
	}
	return txts, err
}

type tempLookupError struct{ error }

func (tempLookupError) Timeout() bool   { return false }
func (tempLookupError) Temporary() bool { return true }
func (e tempLookupError) Unwrap() error { return e.error }

// orgDomain is the registrable domain DMARC's relaxed alignment compares.
func orgDomain(d string) string {
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	if org, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		return org
	}
	return d
}

func aligned(a, b string, mode dmarc.AlignmentMode) bool {
	if a == "" || b == "" {
		return false
	}
	if mode == dmarc.AlignmentStrict {
		return strings.EqualFold(a, b)
	}
	return orgDomain(a) == orgDomain(b)
}

func (r *run) dkimMode() dmarc.AlignmentMode {
	if r.dmarcRec != nil && r.dmarcRec.Rec != nil && r.dmarcRec.Rec.DKIMAlignment != "" {
		return r.dmarcRec.Rec.DKIMAlignment
	}
	return dmarc.AlignmentRelaxed
}

func (r *run) spfMode() dmarc.AlignmentMode {
	if r.dmarcRec != nil && r.dmarcRec.Rec != nil && r.dmarcRec.Rec.SPFAlignment != "" {
		return r.dmarcRec.Rec.SPFAlignment
	}
	return dmarc.AlignmentRelaxed
}

func (r *run) verifyDKIM() {
	// The DMARC record decides strict or relaxed alignment, so read it first.
	r.dmarcRec, r.dmarcErr = r.lookupDMARC()

	var sigs []map[string]string
	for _, v := range r.msg.all("DKIM-Signature") {
		sigs = append(sigs, tagList(v))
	}
	if len(sigs) == 0 {
		r.add(verdict.Check{
			ID: "auth.dkim", Category: verdict.Auth, Status: verdict.Fail,
			Title:  "No DKIM signature",
			Detail: "The message is not signed, so nothing ties it to your domain.",
			Fix:    &verdict.Fix{Who: verdict.FixedByYou, Text: "Turn on DKIM signing with your own domain in your email platform, then publish the DNS records it gives you."},
			Docs:   docsGmail,
		})
		r.fp.Auth["dkim"] = verdict.Fail
		return
	}

	verifs, err := dkim.VerifyWithOptions(bytes.NewReader(r.msg.Raw), &dkim.VerifyOptions{
		LookupTXT:        r.dkimLookupTXT,
		MaxVerifications: 8,
	})
	if err != nil && !errors.Is(err, dkim.ErrTooManySignatures) {
		r.add(verdict.Check{
			ID: "auth.dkim", Category: verdict.Auth, Status: verdict.Fail,
			Title: "DKIM could not be verified", Detail: err.Error(),
		})
		r.fp.Auth["dkim"] = verdict.Fail
		return
	}

	offline, temp, expired := 0, 0, 0
	now := time.Now()
	for i, sig := range sigs {
		if i >= len(verifs) {
			break
		}
		v := verifs[i]
		d := dkimResult{
			Domain:    strings.ToLower(sig["d"]),
			Selector:  sig["s"],
			Algorithm: sig["a"],
			Result:    "pass",
		}
		if v.Domain != "" {
			d.Domain = strings.ToLower(v.Domain)
		}
		d.HeaderKeys = v.HeaderKeys
		switch {
		case v.Err == nil:
		case !v.Expiration.IsZero() && now.After(v.Expiration) && !r.opts.ReceivedAt.After(v.Expiration):
			// go-msgauth checks x= against the clock, before anything else.
			// The signature was still valid when the message arrived, so
			// whether it verified then cannot be known now.
			d.Result, d.Error, d.ExpiredAfterReceipt = "permerror", v.Err.Error(), true
			expired++
		case errors.Is(v.Err, ErrOffline) || strings.Contains(v.Err.Error(), ErrOffline.Error()):
			// The library wraps lookup errors as text, so match the message.
			d.Result, d.Error = "temperror", ErrOffline.Error()
			offline++
		case dkim.IsTempFail(v.Err):
			d.Result, d.Error = "temperror", v.Err.Error()
			temp++
		case dkim.IsPermFail(v.Err):
			d.Result, d.Error = "permerror", v.Err.Error()
		default:
			d.Result, d.Error = "fail", v.Err.Error()
		}
		if d.Result == "pass" {
			d.Aligned = aligned(d.Domain, r.fromDom, r.dkimMode())
			d.KeyType, d.KeyBits = r.dkimKey(d.Selector, d.Domain)
		}
		r.dkim = append(r.dkim, d)
		r.fp.DKIMDomains = appendUnique(r.fp.DKIMDomains, d.Domain)
		r.fp.DKIMSelectors = appendUnique(r.fp.DKIMSelectors, d.Selector+"._domainkey."+d.Domain)
	}

	var ev []map[string]any
	passed := false
	for _, d := range r.dkim {
		ev = append(ev, d.evidence())
		if d.Result == "pass" {
			passed = true
		}
	}
	c := verdict.Check{ID: "auth.dkim", Category: verdict.Auth, Evidence: map[string]any{"signatures": ev}, Docs: docsGmail}
	switch {
	case passed:
		c.Status, c.Title = verdict.Pass, "DKIM signature verified"
	case offline == len(r.dkim):
		c = skipped("auth.dkim", verdict.Auth, "DKIM not verified", "Offline: the signing key could not be looked up.")
		r.authDNS = true
	case offline+temp == len(r.dkim):
		c = skipped("auth.dkim", verdict.Auth, "DKIM not verified", "Temporary DNS failure looking up the signing key. Try again.")
		r.authDNS = true
	case offline+temp+expired == len(r.dkim):
		reason := "The signature expired after the message was received, so it can no longer be verified."
		if offline+temp > 0 {
			reason += " Looking up the signing key for another signature failed."
			r.authDNS = true
		}
		c = skipped("auth.dkim", verdict.Auth, "DKIM not verified", reason)
	case offline+temp+expired > 0:
		// One of the signatures that could not be verified may be good.
		c = skipped("auth.dkim", verdict.Auth, "DKIM not verified", "One signature does not verify, and another could not be verified, so whether DKIM passes is unknown.")
		r.authDNS = offline+temp > 0
	default:
		c.Status, c.Title = verdict.Fail, "No DKIM signature verifies"
		c.Detail = "The message is signed, but no signature checks out against the published key."
		c.Fix = &verdict.Fix{Who: verdict.FixedByProvider, Text: dkimBrokenFix}
	}
	r.fp.Auth["dkim"] = c.Status
	r.add(c)

	if !passed {
		return
	}
	// Key strength of the signatures that verified. When one of them is the
	// publisher's own, only those count, since the platform's key is not
	// theirs to rotate.
	own := false
	for _, d := range r.dkim {
		if d.Result == "pass" && orgDomain(d.Domain) == orgDomain(r.fromDom) {
			own = true
		}
	}
	weakest, weakDom := 0, ""
	for _, d := range r.dkim {
		if d.Result != "pass" || d.KeyType != "rsa" || (own && orgDomain(d.Domain) != orgDomain(r.fromDom)) {
			continue
		}
		if weakest == 0 || d.KeyBits < weakest {
			weakest, weakDom = d.KeyBits, d.Domain
		}
	}
	k := verdict.Check{ID: "auth.dkim_key", Category: verdict.Auth, Evidence: map[string]any{"weakest_rsa_bits": weakest}}
	if weakDom != "" {
		k.Evidence["domain"] = weakDom
	}
	rotate := func(text string) *verdict.Fix {
		if own {
			return &verdict.Fix{Who: verdict.FixedByYou, Text: text}
		}
		return &verdict.Fix{Who: verdict.FixedByProvider, Text: "Ask your email platform to rotate the DKIM key for " + weakDom + " to 2048 bits."}
	}
	switch {
	case weakest == 0:
		k.Status, k.Title = verdict.Info, "DKIM key is not RSA, or could not be sized"
	case weakest < 1024:
		k.Status, k.Title = verdict.Fail, fmt.Sprintf("DKIM key is only %d bits", weakest)
		k.Fix = rotate("Rotate to a 2048-bit DKIM key.")
	case weakest < 2048:
		k.Status, k.Title = verdict.Warn, fmt.Sprintf("DKIM key is %d bits", weakest)
		k.Fix = rotate("Rotate to a 2048-bit DKIM key when you can.")
	default:
		k.Status, k.Title = verdict.Pass, fmt.Sprintf("DKIM key is %d bits", weakest)
	}
	r.add(k)
}

// dkimKey looks up a selector's public key and reports its type and size.
func (r *run) dkimKey(selector, domain string) (string, int) {
	txts, err := r.lookupTXT(selector + "._domainkey." + domain)
	if err != nil {
		return "", 0
	}
	tags := tagList(strings.Join(txts, ""))
	b, err := base64.StdEncoding.DecodeString(tags["p"])
	if err != nil || len(b) == 0 {
		return "", 0
	}
	if strings.EqualFold(tags["k"], "ed25519") {
		return "ed25519", ed25519.PublicKeySize * 8
	}
	if pub, err := x509.ParsePKIXPublicKey(b); err == nil {
		if k, ok := pub.(*rsa.PublicKey); ok {
			return "rsa", k.N.BitLen()
		}
	}
	if k, err := x509.ParsePKCS1PublicKey(b); err == nil {
		return "rsa", k.N.BitLen()
	}
	return "", 0
}

// spfSender is the envelope sender SPF checks, falling back to the
// Return-Path the receiving server wrote.
func (r *run) spfSender() string {
	if s := r.opts.Envelope.MailFrom; s != "" {
		return strings.Trim(s, "<>")
	}
	return strings.Trim(strings.TrimSpace(r.msg.Header.Get("Return-Path")), "<>")
}

func (r *run) checkSPF() {
	sender := r.spfSender()
	r.spfDom = addrDomain(sender)
	if r.spfDom == "" {
		r.spfDom = strings.ToLower(r.opts.Envelope.Helo)
	}
	r.fp.ReturnPathDomain = r.spfDom

	ip := r.opts.Envelope.RemoteIP
	if ip == nil {
		r.add(skipped("auth.spf", verdict.Auth, "SPF not checked",
			"No envelope: SPF needs the IP address that delivered the message. Pass --ip and --mail-from, or send the message to a SendScore address."))
		r.spfRes = verdict.Skipped
		return
	}
	r.fp.RemoteIP = ip.String()
	if r.spfDom == "" {
		r.add(skipped("auth.spf", verdict.Auth, "SPF not checked", "There is no envelope sender, Return-Path, or HELO name to check SPF for."))
		r.spfRes = verdict.Skipped
		return
	}

	res, err := spf.CheckHostWithSender(ip, r.opts.Envelope.Helo, sender,
		spf.WithResolver(r.res), spf.WithContext(r.ctx))
	c := verdict.Check{
		ID: "auth.spf", Category: verdict.Auth, Docs: docsSPF,
		Evidence: map[string]any{"result": string(res), "ip": ip.String(), "domain": r.spfDom},
	}
	if err != nil {
		c.Evidence["error"] = err.Error()
	}
	who := verdict.FixedByProvider
	if orgDomain(r.spfDom) == orgDomain(r.fromDom) {
		who = verdict.FixedByYou
	}
	offline := err != nil && (errors.Is(err, ErrOffline) || strings.Contains(err.Error(), ErrOffline.Error()))
	switch {
	case offline:
		res = spf.TempError
	case res == spf.PermError && isDNSFailure(err):
		// The library calls any lookup error that is not marked temporary a
		// permerror. A failed lookup means SPF could not be evaluated.
		res = spf.TempError
	}
	switch res {
	case spf.Pass:
		c.Status, c.Title = verdict.Pass, "SPF passes for "+r.spfDom
	case spf.Neutral:
		c.Status, c.Title = verdict.Warn, "SPF is neutral for "+r.spfDom
		c.Fix = &verdict.Fix{Who: who, Text: "End the SPF record for " + r.spfDom + " with -all or ~all, and include your email platform."}
	case spf.TempError:
		reason := "Temporary DNS failure. " + fmt.Sprint(err)
		if offline {
			reason = lookupFailed(ErrOffline)
		}
		c = skipped("auth.spf", verdict.Auth, "SPF not checked", reason)
		r.spfTemp = true
		r.authDNS = true
	default:
		c.Status, c.Title = verdict.Fail, "SPF "+string(res)+" for "+r.spfDom
		c.Fix = &verdict.Fix{Who: who, Text: "Add your email platform to the SPF record for " + r.spfDom + "."}
	}
	r.spfRes = c.Status
	r.fp.Auth["spf"] = c.Status
	r.add(c)
}

// isDNSFailure is a lookup that failed, as opposed to a name that does not
// exist or an error in the record itself. A canceled or expired context
// counts as a failed lookup.
func isDNSFailure(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && !dnsErr.IsNotFound
}

// checkSPFLookups walks the SPF record the way a receiver does and reports
// the permanent errors every receiver would hit (RFC 7208, section 4.6.4):
// more than ten DNS lookups, more than two lookups that find nothing, more
// than one SPF record, or an include with no SPF record.
func (r *run) checkSPFLookups() {
	if r.spfDom == "" {
		r.add(skipped("auth.spf_lookups", verdict.Auth, "SPF record not inspected", "No Return-Path or envelope sender to look up."))
		return
	}
	who := verdict.FixedByProvider
	if orgDomain(r.spfDom) == orgDomain(r.fromDom) {
		who = verdict.FixedByYou
	}
	w := &spfWalk{r: r}
	err := w.walk(r.spfDom, "")
	if errors.Is(err, errNoSPF) {
		r.add(verdict.Check{
			ID: "auth.spf_lookups", Category: verdict.Auth, Status: verdict.Fail,
			Title:    "No SPF record for " + r.spfDom,
			Evidence: map[string]any{"domain": r.spfDom},
			Fix:      &verdict.Fix{Who: who, Text: "Publish an SPF record for " + r.spfDom + " that includes the sending servers."},
			Docs:     docsSPF,
		})
		return
	}
	if err != nil {
		reason := lookupFailed(err)
		if reason == "" || errors.Is(err, errSPFQueries) {
			reason = err.Error()
		}
		r.add(skipped("auth.spf_lookups", verdict.Auth, "SPF record not inspected", reason))
		return
	}
	c := verdict.Check{
		ID: "auth.spf_lookups", Category: verdict.Auth, Docs: docsSPF + "#section-4.6.4",
		Evidence: map[string]any{
			"domain": r.spfDom, "lookups": w.lookups, "limit": spfLookupLimit,
			"void_lookups": len(w.voids),
		},
	}
	if len(w.voids) > 0 {
		c.Evidence["void_names"] = w.voids
	}
	const permerror = "Receivers treat this as a permanent SPF error, so SPF fails for every message."
	switch {
	case w.problem != nil:
		p := w.problem
		c.Status, c.Detail = verdict.Fail, permerror
		c.Evidence["problem"], c.Evidence["problem_domain"] = p.kind, p.domain
		switch p.kind {
		case "multiple":
			c.Title = "More than one SPF record for " + p.domain
			c.Fix = &verdict.Fix{Who: who, Text: "Merge the SPF records for " + p.domain + " into one TXT record that starts with v=spf1."}
		case "include":
			c.Title = "SPF includes " + p.domain + ", which has no SPF record"
			c.Fix = &verdict.Fix{Who: who, Text: "Remove include:" + p.domain + " from the SPF record for " + r.spfDom + ", or correct the domain name."}
		case "redirect":
			c.Title = "SPF redirects to " + p.domain + ", which has no SPF record"
			c.Fix = &verdict.Fix{Who: who, Text: "Point redirect= in the SPF record for " + r.spfDom + " at a domain that publishes SPF."}
		case "loop":
			c.Title = "SPF record for " + p.domain + " includes itself"
			c.Fix = &verdict.Fix{Who: who, Text: "Remove the include or redirect that leads back to " + p.domain + " from the SPF record."}
		case "voids":
			c.Title = "SPF has more than two lookups that find nothing"
			c.Fix = &verdict.Fix{Who: who, Text: "Remove the mechanisms in the SPF record for " + r.spfDom + " that name hosts with no DNS records."}
		}
	case w.lookups > spfLookupLimit:
		c.Status, c.Title, c.Detail = verdict.Fail, "SPF needs more than 10 DNS lookups", permerror
		c.Fix = &verdict.Fix{Who: who, Text: "Remove includes that are no longer used from the SPF record for " + r.spfDom + "."}
	case w.lookups >= 8:
		c.Status, c.Title = verdict.Warn, fmt.Sprintf("SPF needs %d of 10 DNS lookups", w.lookups)
		c.Detail = "One more include will break SPF for every message."
	default:
		c.Status, c.Title = verdict.Pass, fmt.Sprintf("SPF needs %d of 10 DNS lookups", w.lookups)
	}
	r.add(c)
}

const (
	spfLookupLimit = 10
	spfVoidLimit   = 2
	// maxSPFQueries bounds the DNS queries one walk makes. The walk stops at
	// the lookup limit long before this; it is a backstop.
	maxSPFQueries = 40
)

var (
	errNoSPF       = errors.New("no SPF record")
	errMultipleSPF = errors.New("more than one SPF record")
	errSPFQueries  = fmt.Errorf("Stopped after %d DNS queries without finishing the SPF record.", maxSPFQueries)
)

// spfWalk counts lookups per include path, as receivers do, so an include
// reached twice is counted twice. It stops at the first permanent error.
type spfWalk struct {
	r       *run
	lookups int
	voids   []string
	queries int
	path    []string
	problem *spfProblem
}

type spfProblem struct{ kind, domain string }

func (w *spfWalk) done() bool { return w.problem != nil || w.lookups > spfLookupLimit }

func (w *spfWalk) fail(kind, domain string) {
	if w.problem == nil {
		w.problem = &spfProblem{kind, domain}
	}
}

func (w *spfWalk) record(domain string) (string, error) {
	if w.queries++; w.queries > maxSPFQueries {
		return "", errSPFQueries
	}
	txts, err := w.r.lookupTXT(domain)
	if err != nil {
		if lookupFailed(err) == "" {
			return "", errNoSPF
		}
		return "", err
	}
	var recs []string
	for _, t := range txts {
		if l := strings.ToLower(t); l == "v=spf1" || strings.HasPrefix(l, "v=spf1 ") {
			recs = append(recs, t)
		}
	}
	switch len(recs) {
	case 0:
		return "", errNoSPF
	case 1:
		return recs[0], nil
	}
	return "", errMultipleSPF
}

// walk follows one record. via is how it was reached: "" for the top,
// "include", or "redirect". Only DNS failures come back as errors.
func (w *spfWalk) walk(domain, via string) error {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if strings.Contains(domain, "%") {
		// A name built from macros depends on the sender, so it is counted
		// but not followed.
		return nil
	}
	if slices.Contains(w.path, domain) {
		w.fail("loop", domain)
		return nil
	}
	rec, err := w.record(domain)
	switch {
	case errors.Is(err, errNoSPF) && via != "":
		w.fail(via, domain)
		return nil
	case errors.Is(err, errMultipleSPF):
		w.fail("multiple", domain)
		return nil
	case err != nil:
		return err
	}
	w.path = append(w.path, domain)
	defer func() { w.path = w.path[:len(w.path)-1] }()

	redirect, hasAll := "", false
	for _, term := range strings.Fields(rec)[1:] {
		if w.done() {
			return nil
		}
		t := strings.ToLower(term)
		if v, ok := strings.CutPrefix(t, "redirect="); ok {
			redirect = v
			continue
		}
		mech, target := spfMechanism(strings.TrimLeft(t, "+-~?"))
		if target == "" {
			target = domain
		}
		switch mech {
		case "all":
			hasAll = true
			continue
		case "include", "a", "mx", "ptr", "exists":
		default:
			continue
		}
		if w.lookups++; w.done() {
			return nil
		}
		switch mech {
		case "include":
			err = w.walk(target, "include")
		case "a", "mx", "exists":
			err = w.resolve(mech, target)
		}
		if err != nil {
			return err
		}
	}
	// A redirect only applies when the record has no all mechanism
	// (RFC 7208, section 6.1).
	if redirect == "" || hasAll || w.done() {
		return nil
	}
	if w.lookups++; w.done() {
		return nil
	}
	return w.walk(redirect, "redirect")
}

// resolve looks up the host an a, mx, or exists mechanism names, to count the
// lookups that find nothing. A name built from macros depends on the sender,
// so it is not looked up.
func (w *spfWalk) resolve(mech, host string) error {
	if strings.Contains(host, "%") {
		return nil
	}
	if w.queries++; w.queries > maxSPFQueries {
		return errSPFQueries
	}
	n := 0
	var err error
	if mech == "mx" {
		var mxs []*net.MX
		mxs, err = w.r.res.LookupMX(w.r.ctx, host)
		n = len(mxs)
	} else {
		var ips []net.IPAddr
		ips, err = w.r.res.LookupIPAddr(w.r.ctx, host)
		n = len(ips)
	}
	if lookupFailed(err) != "" {
		return err
	}
	if n == 0 {
		w.voids = append(w.voids, host)
		if len(w.voids) > spfVoidLimit {
			w.fail("voids", host)
		}
	}
	return nil
}

// spfMechanism splits "mx:example.com/24" into "mx" and "example.com".
func spfMechanism(t string) (string, string) {
	name, target := t, ""
	if i := strings.IndexAny(t, ":/"); i >= 0 {
		name = t[:i]
		if t[i] == ':' {
			target = t[i+1:]
		}
	}
	if i := strings.Index(target, "/"); i >= 0 {
		target = target[:i]
	}
	return name, target
}

var (
	errMultipleDMARC = errors.New("more than one DMARC record")
	errNoFromDomain  = errors.New("The message has no From domain.")
)

// lookupDMARC finds the policy for the From domain, falling back to its
// organizational domain (RFC 7489, section 6.6.3). More than one record at a
// name ends discovery, and no policy applies.
func (r *run) lookupDMARC() (*dmarcRecord, error) {
	if r.fromDom == "" {
		return nil, errNoFromDomain
	}
	domains := []string{r.fromDom}
	if org := orgDomain(r.fromDom); org != r.fromDom {
		domains = append(domains, org)
	}
	for _, d := range domains {
		txts, err := r.lookupTXT("_dmarc." + d)
		if err != nil {
			if lookupFailed(err) != "" {
				return nil, err
			}
			continue
		}
		var recs []string
		for _, t := range txts {
			if strings.HasPrefix(t, "v=DMARC1") {
				recs = append(recs, t)
			}
		}
		switch {
		case len(recs) == 0:
			continue
		case len(recs) > 1:
			return &dmarcRecord{Domain: d, Records: recs}, errMultipleDMARC
		}
		rec, err := dmarc.Parse(recs[0])
		if err != nil {
			if t := tolerantDMARC(recs[0]); t != nil {
				return &dmarcRecord{Domain: d, Raw: recs[0], Rec: t, ParseErr: err}, nil
			}
			return &dmarcRecord{Domain: d, Raw: recs[0]}, err
		}
		return &dmarcRecord{Domain: d, Raw: recs[0], Rec: rec}, nil
	}
	return nil, dmarc.ErrNoPolicy
}

// policy is the policy that applies to the From domain: sp= when the record
// came from the organizational domain and sets one, p= otherwise.
func (d *dmarcRecord) policy(fromDom string) (dmarc.Policy, string) {
	if d.Domain != fromDom && d.Rec.SubdomainPolicy != "" {
		return d.Rec.SubdomainPolicy, "sp"
	}
	return d.Rec.Policy, "p"
}

// dmarcUnknown says why the DMARC record could not be read, or "" when it
// was read or does not exist.
func (r *run) dmarcUnknown() string {
	rec, err := r.dmarcRec, r.dmarcErr
	if rec != nil || err == nil || errors.Is(err, dmarc.ErrNoPolicy) {
		return ""
	}
	if errors.Is(err, errNoFromDomain) {
		return err.Error()
	}
	if reason := lookupFailed(err); reason != "" {
		return reason
	}
	return err.Error()
}

func (r *run) checkDMARCRecord() {
	if reason := r.dmarcUnknown(); reason != "" {
		if !errors.Is(r.dmarcErr, errNoFromDomain) {
			r.authDNS = true
		}
		r.add(skipped("auth.dmarc_record", verdict.Auth, "DMARC record not checked", reason))
		return
	}
	rec, err := r.dmarcRec, r.dmarcErr
	c := verdict.Check{ID: "auth.dmarc_record", Category: verdict.Auth, Docs: docsGmail}
	switch {
	case rec == nil:
		c.Status, c.Title = verdict.Fail, "No DMARC record for "+r.fromDom
		c.Evidence = map[string]any{"domain": r.fromDom}
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Publish a TXT record at _dmarc." + orgDomain(r.fromDom) + " such as \"v=DMARC1; p=none; rua=mailto:dmarc@" + orgDomain(r.fromDom) + "\"."}
	case len(rec.Records) > 1:
		c.Status, c.Title = verdict.Fail, "More than one DMARC record at _dmarc."+rec.Domain
		c.Detail = "When a domain publishes more than one DMARC record, receivers apply none of them, so the domain has no DMARC policy."
		c.Evidence = map[string]any{"domain": rec.Domain, "records": rec.Records}
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Delete all but one of the DMARC records at _dmarc." + rec.Domain + "."}
	case rec.Rec == nil:
		c.Status, c.Title = verdict.Fail, "DMARC record does not parse"
		c.Evidence = map[string]any{"domain": rec.Domain, "record": rec.Raw, "error": fmt.Sprint(err)}
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Fix the syntax of the DMARC record at _dmarc." + rec.Domain + "."}
	default:
		p, tag := rec.policy(r.fromDom)
		c.Evidence = map[string]any{"domain": rec.Domain, "record": rec.Raw, "policy": string(p), "policy_tag": tag}
		if rec.ParseErr != nil {
			c.Status, c.Title = verdict.Warn, "DMARC record has a syntax error, but its policy is "+string(p)
			c.Detail = "Receivers are told to ignore what they cannot read and apply the policy, but not all of them do."
			c.Evidence["error"] = rec.ParseErr.Error()
			c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Fix the syntax of the DMARC record at _dmarc." + rec.Domain + "."}
		} else if p == dmarc.PolicyNone && len(rec.Rec.ReportURIAggregate) == 0 {
			c.Status, c.Title = verdict.Warn, "DMARC policy is none, with no reports"
			c.Detail = "A policy of none meets the bulk sender rules, but without rua you never see who is sending as your domain."
			c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Add rua=mailto:... to the DMARC record so you receive aggregate reports."}
		} else {
			c.Status, c.Title = verdict.Pass, "DMARC policy is "+string(p)
		}
	}
	r.add(c)
}

// authAlignment is what DMARC needs from DKIM and SPF. unknown is set when a
// result that could have aligned was hidden, by a DNS failure, a missing
// envelope, or a signature that has since expired, so neither a pass nor a
// failure can be claimed. why says what was hidden.
type authAlignment struct {
	dkim, spf bool
	unknown   bool
	why       []string
	// dkimUnknown is an aligned signature that could not be verified.
	dkimUnknown bool
	// dkimBroken is a signature for the From domain that did not verify.
	dkimBroken string
}

func (a *authAlignment) hidden(why string) {
	a.unknown = true
	if !slices.Contains(a.why, why) {
		a.why = append(a.why, why)
	}
}

func (r *run) alignment() authAlignment {
	var a authAlignment
	for _, d := range r.dkim {
		if !aligned(d.Domain, r.fromDom, r.dkimMode()) {
			continue
		}
		switch {
		case d.Result == "pass":
			a.dkim = true
		case d.Result == "temperror":
			a.dkimUnknown = true
			a.hidden("The DKIM signature for " + d.Domain + " could not be verified because DNS failed or was offline.")
		case d.ExpiredAfterReceipt:
			a.dkimUnknown = true
			a.hidden("The DKIM signature for " + d.Domain + " expired after the message was received, so it can no longer be verified.")
		default:
			a.dkimBroken = d.Domain
		}
	}
	spfAligns := aligned(r.spfDom, r.fromDom, r.spfMode())
	a.spf = r.spfRes == verdict.Pass && spfAligns
	switch {
	case r.spfTemp && spfAligns:
		a.hidden("SPF for " + r.spfDom + " could not be checked because DNS failed or was offline.")
	case r.spfRes == verdict.Skipped && !r.spfTemp && spfAligns:
		// A saved message has no envelope, but its Return-Path aligns, so
		// SPF could have passed DMARC when it was delivered.
		a.hidden("SPF was not checked because there is no envelope, and the Return-Path domain " + r.spfDom + " aligns with the From domain.")
	}
	if r.spfRes == verdict.Skipped && r.spfDom == "" {
		// Whether SPF could have aligned is unknown without a domain to test.
		a.hidden("SPF was not checked because the message has no Return-Path.")
	}
	if r.fp.Auth["dkim"] == verdict.Skipped && r.spfRes == verdict.Skipped {
		a.hidden("Neither DKIM nor SPF could be checked.")
	}
	if a.dkim || a.spf {
		a.unknown, a.why = false, nil
	}
	return a
}

func (r *run) checkDMARC() {
	a := r.alignment()
	ev := map[string]any{"from_domain": r.fromDom, "dkim_aligned": a.dkim, "spf_aligned": a.spf}
	hasPolicy := r.dmarcRec != nil && r.dmarcRec.Rec != nil
	if hasPolicy {
		p, _ := r.dmarcRec.policy(r.fromDom)
		ev["policy"] = string(p)
	}
	c := verdict.Check{ID: "auth.dmarc", Category: verdict.Auth, Evidence: ev, Docs: docsDMARC}
	dkimFix := &verdict.Fix{Who: verdict.FixedByYou, Text: "Set up DKIM with your own domain (" + r.fromDom + ") in your email platform, so messages are signed as you rather than as the platform."}
	if a.dkimBroken != "" {
		// The domain is set up. Its signature breaks, which auth.dkim reports.
		dkimFix = &verdict.Fix{Who: verdict.FixedByProvider, Text: dkimBrokenFix}
	}
	switch {
	case errors.Is(r.dmarcErr, errNoFromDomain):
		c = skipped("auth.dmarc", verdict.Auth, "DMARC not evaluated", "The message has no From domain to check DMARC for.")
	case r.multiFrom:
		c = skipped("auth.dmarc", verdict.Auth, "DMARC not evaluated", "The message has more than one From address, and DMARC needs exactly one. See struct.headers.")
	case r.dmarcUnknown() != "":
		c = skipped("auth.dmarc", verdict.Auth, "DMARC not evaluated", "The DMARC record could not be read. "+r.dmarcUnknown())
	case !hasPolicy:
		c.Status, c.Title = verdict.Info, "No DMARC policy applies"
		c.Detail = "Without exactly one valid DMARC record, the DMARC result is none whatever aligns. See auth.dmarc_record."
	case a.dkim || a.spf:
		c.Status, c.Title = verdict.Pass, "DMARC passes"
	case a.unknown:
		c = skipped("auth.dmarc", verdict.Auth, "DMARC not evaluated", strings.Join(a.why, " ")+" Whether DMARC passes is unknown until that can be checked.")
	case r.spfRes == verdict.Skipped:
		c.Status, c.Title = verdict.Fail, "DMARC does not align through DKIM"
		if a.dkimBroken != "" {
			c.Detail = "SPF was not checked, and the DKIM signature for " + a.dkimBroken + " does not verify."
		} else {
			c.Detail = "SPF was not checked, and no DKIM signature uses the From domain " + r.fromDom + "."
		}
		c.Fix = dkimFix
	default:
		c.Status, c.Title = verdict.Fail, "DMARC does not align"
		if a.dkimBroken != "" {
			c.Detail = "SPF does not pass for the From domain " + r.fromDom + ", and the DKIM signature for " + a.dkimBroken + " does not verify."
		} else {
			c.Detail = "Neither a passing DKIM signature nor a passing SPF check uses the From domain " + r.fromDom + "."
		}
		c.Fix = dkimFix
	}
	r.fp.Auth["dmarc"] = c.Status
	r.add(c)
}

func (r *run) checkAlignment() {
	a := r.alignment()
	c := verdict.Check{
		ID: "auth.alignment", Category: verdict.Auth,
		Evidence: map[string]any{
			"from_domain": r.fromDom, "spf_domain": r.spfDom,
			"dkim_mode": string(r.dkimMode()), "spf_mode": string(r.spfMode()),
			"dkim_aligned": a.dkim, "spf_aligned": a.spf,
		},
	}
	switch {
	case a.dkim:
		c.Status, c.Title = verdict.Pass, "DKIM aligns with the From domain"
	case a.spf && a.dkimUnknown:
		c = skipped("auth.alignment", verdict.Auth, "DKIM alignment not checked", "SPF aligns with the From domain, but a DKIM signature for the From domain could not be verified, so whether DKIM aligns is unknown.")
	case a.spf:
		c.Status, c.Title = verdict.Warn, "Only SPF aligns with the From domain"
		c.Detail = "SPF alignment breaks when a subscriber forwards the message. DKIM alignment survives it."
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Set up DKIM with your own domain as well."}
	case a.unknown:
		c = skipped("auth.alignment", verdict.Auth, "Alignment not checked", "DKIM or SPF could not be checked, so whether they align is unknown.")
	default:
		c.Status, c.Title = verdict.Info, "Nothing aligns with the From domain"
		c.Detail = "See auth.dmarc."
	}
	r.add(c)
}

// maxPTRNames is how many reverse DNS names checkPTR looks up.
const maxPTRNames = 10

func (r *run) checkPTR() {
	ip := r.opts.Envelope.RemoteIP
	if ip == nil {
		r.add(skipped("auth.ptr", verdict.Auth, "Reverse DNS not checked", "No envelope: the delivering IP address is unknown."))
		return
	}
	names, err := r.res.LookupAddr(r.ctx, ip.String())
	if reason := lookupFailed(err); reason != "" {
		r.add(skipped("auth.ptr", verdict.Auth, "Reverse DNS not checked", reason))
		return
	}
	c := verdict.Check{
		ID: "auth.ptr", Category: verdict.Auth, Docs: docsGmail,
		Evidence: map[string]any{"ip": ip.String()},
		Fix:      &verdict.Fix{Who: verdict.FixedByProvider, Text: "The sending server needs reverse DNS that resolves back to its own address. Only your email platform can set this."},
	}
	capped(c.Evidence, "ptr", names)
	// The sender controls its reverse zone, so only the first names are
	// looked up, as RFC 7208 section 5.5 does.
	lookup := names
	if len(lookup) > maxPTRNames {
		lookup = lookup[:maxPTRNames]
		c.Detail = fmt.Sprintf("Only the first %d of %d reverse DNS names were looked up.", maxPTRNames, len(names))
	}
	var failed error
	for _, n := range lookup {
		addrs, err := r.res.LookupIPAddr(r.ctx, strings.TrimSuffix(n, "."))
		if lookupFailed(err) != "" {
			failed = err
			continue
		}
		for _, a := range addrs {
			if a.IP.Equal(ip) {
				r.fp.PTR = strings.ToLower(strings.TrimSuffix(n, "."))
				c.Status, c.Title, c.Fix = verdict.Pass, "Reverse DNS matches ("+r.fp.PTR+")", nil
				r.add(c)
				return
			}
		}
	}
	if failed != nil {
		r.add(skipped("auth.ptr", verdict.Auth, "Reverse DNS not checked", lookupFailed(failed)))
		return
	}
	if len(names) == 0 {
		c.Status, c.Title = verdict.Fail, "Sending IP has no reverse DNS"
	} else {
		c.Status, c.Title = verdict.Fail, "Reverse DNS does not resolve back to the sending IP"
	}
	r.add(c)
}

func (r *run) checkTLS() {
	t := r.opts.Envelope.TLS
	if t == nil {
		r.add(skipped("auth.tls", verdict.Auth, "TLS not checked", "No envelope: how the message was delivered is unknown."))
		return
	}
	if *t {
		r.add(verdict.Check{ID: "auth.tls", Category: verdict.Auth, Status: verdict.Pass, Title: "Delivered over TLS"})
		return
	}
	r.add(verdict.Check{
		ID: "auth.tls", Category: verdict.Auth, Status: verdict.Fail, Title: "Delivered without TLS",
		Fix:  &verdict.Fix{Who: verdict.FixedByProvider, Text: "Gmail requires bulk mail over TLS. Ask your email platform why it did not use STARTTLS."},
		Docs: docsGmail,
	})
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
