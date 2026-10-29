package engine

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

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
	return e
}

type dmarcRecord struct {
	Domain string
	Raw    string
	Rec    *dmarc.Record
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
		LookupTXT:        r.lookupTXT,
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

	offline, temp := 0, 0
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
	case offline+temp == len(r.dkim):
		c = skipped("auth.dkim", verdict.Auth, "DKIM not verified", "Temporary DNS failure looking up the signing key. Try again.")
	default:
		c.Status, c.Title = verdict.Fail, "No DKIM signature verifies"
		c.Detail = "The message is signed, but no signature checks out against the published key."
		c.Fix = &verdict.Fix{Who: verdict.FixedByProvider, Text: "Ask your email platform why its DKIM signature fails; something is changing the message after signing, or the published key does not match."}
	}
	r.fp.Auth["dkim"] = c.Status
	r.add(c)

	if !passed {
		return
	}
	// Key strength of the signatures that verified.
	weakest := 0
	for _, d := range r.dkim {
		if d.Result == "pass" && d.KeyType == "rsa" && (weakest == 0 || d.KeyBits < weakest) {
			weakest = d.KeyBits
		}
	}
	k := verdict.Check{ID: "auth.dkim_key", Category: verdict.Auth, Evidence: map[string]any{"weakest_rsa_bits": weakest}}
	switch {
	case weakest == 0:
		k.Status, k.Title = verdict.Info, "DKIM key is not RSA, or could not be sized"
	case weakest < 1024:
		k.Status, k.Title = verdict.Fail, fmt.Sprintf("DKIM key is only %d bits", weakest)
		k.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Rotate to a 2048-bit DKIM key."}
	case weakest < 2048:
		k.Status, k.Title = verdict.Warn, fmt.Sprintf("DKIM key is %d bits", weakest)
		k.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Rotate to a 2048-bit DKIM key when you can."}
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
	switch res {
	case spf.Pass:
		c.Status, c.Title = verdict.Pass, "SPF passes for "+r.spfDom
	case spf.Neutral:
		c.Status, c.Title = verdict.Warn, "SPF is neutral for "+r.spfDom
		c.Fix = &verdict.Fix{Who: who, Text: "End the SPF record for " + r.spfDom + " with -all or ~all, and include your email platform."}
	case spf.TempError:
		c = skipped("auth.spf", verdict.Auth, "SPF not checked", "Temporary DNS failure: "+fmt.Sprint(err))
	default:
		c.Status, c.Title = verdict.Fail, "SPF "+string(res)+" for "+r.spfDom
		c.Fix = &verdict.Fix{Who: who, Text: "Add your email platform to the SPF record for " + r.spfDom + "."}
	}
	r.spfRes = c.Status
	r.fp.Auth["spf"] = c.Status
	r.add(c)
}

// checkSPFLookups counts the DNS lookups the SPF record costs. Over ten is a
// permanent error for every receiver (RFC 7208, section 4.6.4).
func (r *run) checkSPFLookups() {
	if r.spfDom == "" {
		r.add(skipped("auth.spf_lookups", verdict.Auth, "SPF record not inspected", "No Return-Path or envelope sender to look up."))
		return
	}
	n, err := r.countSPF(r.spfDom, 0, map[string]bool{})
	if reason := lookupFailed(err); reason != "" {
		r.add(skipped("auth.spf_lookups", verdict.Auth, "SPF record not inspected", reason))
		return
	}
	if errors.Is(err, errNoSPF) || err != nil {
		r.add(verdict.Check{
			ID: "auth.spf_lookups", Category: verdict.Auth, Status: verdict.Fail,
			Title:    "No SPF record for " + r.spfDom,
			Evidence: map[string]any{"domain": r.spfDom},
			Fix:      &verdict.Fix{Who: verdict.FixedByProvider, Text: "Publish an SPF record for " + r.spfDom + " that includes the sending servers."},
			Docs:     docsSPF,
		})
		return
	}
	c := verdict.Check{
		ID: "auth.spf_lookups", Category: verdict.Auth, Docs: docsSPF + "#section-4.6.4",
		Evidence: map[string]any{"domain": r.spfDom, "lookups": n, "limit": 10},
	}
	switch {
	case n > 10:
		c.Status, c.Title = verdict.Fail, fmt.Sprintf("SPF needs %d DNS lookups (limit 10)", n)
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Remove includes you no longer use from the SPF record for " + r.spfDom + "."}
	case n >= 8:
		c.Status, c.Title = verdict.Warn, fmt.Sprintf("SPF needs %d of 10 DNS lookups", n)
		c.Detail = "One more include will break SPF for every message."
	default:
		c.Status, c.Title = verdict.Pass, fmt.Sprintf("SPF needs %d of 10 DNS lookups", n)
	}
	r.add(c)
}

var errNoSPF = errors.New("no SPF record")

func (r *run) spfRecord(domain string) (string, error) {
	txts, err := r.lookupTXT(domain)
	if err != nil {
		if lookupFailed(err) == "" {
			return "", errNoSPF
		}
		return "", err
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			return t, nil
		}
	}
	return "", errNoSPF
}

func (r *run) countSPF(domain string, depth int, seen map[string]bool) (int, error) {
	if depth > 10 || seen[domain] {
		return 0, nil
	}
	seen[domain] = true
	rec, err := r.spfRecord(domain)
	if err != nil {
		if depth > 0 && errors.Is(err, errNoSPF) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	for _, term := range strings.Fields(rec)[1:] {
		t := strings.ToLower(strings.TrimLeft(term, "+-~?"))
		switch {
		case strings.HasPrefix(t, "include:"):
			n++
			sub, err := r.countSPF(strings.TrimPrefix(t, "include:"), depth+1, seen)
			if err != nil && lookupFailed(err) != "" {
				return 0, err
			}
			n += sub
		case strings.HasPrefix(t, "redirect="):
			n++
			sub, err := r.countSPF(strings.TrimPrefix(t, "redirect="), depth+1, seen)
			if err != nil && lookupFailed(err) != "" {
				return 0, err
			}
			n += sub
		case t == "a" || strings.HasPrefix(t, "a:") || strings.HasPrefix(t, "a/"),
			t == "mx" || strings.HasPrefix(t, "mx:") || strings.HasPrefix(t, "mx/"),
			t == "ptr" || strings.HasPrefix(t, "ptr:"),
			strings.HasPrefix(t, "exists:"):
			n++
		}
	}
	return n, nil
}

// lookupDMARC finds the policy for the From domain, falling back to its
// organizational domain (RFC 7489, section 6.6.3).
func (r *run) lookupDMARC() (*dmarcRecord, error) {
	if r.fromDom == "" {
		return nil, errors.New("no From domain")
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
		for _, t := range txts {
			if !strings.HasPrefix(t, "v=DMARC1") {
				continue
			}
			rec, err := dmarc.Parse(t)
			if err != nil {
				return &dmarcRecord{Domain: d, Raw: t}, err
			}
			return &dmarcRecord{Domain: d, Raw: t, Rec: rec}, nil
		}
	}
	return nil, dmarc.ErrNoPolicy
}

func (r *run) checkDMARCRecord() {
	rec, err := r.dmarcRec, r.dmarcErr
	if rec == nil && err != nil && !errors.Is(err, dmarc.ErrNoPolicy) {
		reason := lookupFailed(err)
		if reason == "" {
			reason = err.Error()
		}
		r.add(skipped("auth.dmarc_record", verdict.Auth, "DMARC record not checked", reason))
		return
	}
	c := verdict.Check{ID: "auth.dmarc_record", Category: verdict.Auth, Docs: docsGmail}
	switch {
	case rec == nil:
		c.Status, c.Title = verdict.Fail, "No DMARC record for "+r.fromDom
		c.Evidence = map[string]any{"domain": r.fromDom}
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Publish a TXT record at _dmarc." + orgDomain(r.fromDom) + " such as \"v=DMARC1; p=none; rua=mailto:dmarc@" + orgDomain(r.fromDom) + "\"."}
	case rec.Rec == nil:
		c.Status, c.Title = verdict.Fail, "DMARC record does not parse"
		c.Evidence = map[string]any{"domain": rec.Domain, "record": rec.Raw, "error": fmt.Sprint(err)}
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Fix the syntax of the DMARC record at _dmarc." + rec.Domain + "."}
	default:
		c.Evidence = map[string]any{"domain": rec.Domain, "record": rec.Raw, "policy": string(rec.Rec.Policy)}
		if rec.Rec.Policy == dmarc.PolicyNone && len(rec.Rec.ReportURIAggregate) == 0 {
			c.Status, c.Title = verdict.Warn, "DMARC policy is none, with no reports"
			c.Detail = "p=none meets the bulk sender rules, but without rua you never see who is sending as your domain."
			c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Add rua=mailto:... to the DMARC record so you receive aggregate reports."}
		} else {
			c.Status, c.Title = verdict.Pass, "DMARC policy is "+string(rec.Rec.Policy)
		}
	}
	r.add(c)
}

func (r *run) checkDMARC() {
	dkimAligned := false
	for _, d := range r.dkim {
		if d.Result == "pass" && d.Aligned {
			dkimAligned = true
		}
	}
	spfAligned := r.spfRes == verdict.Pass && aligned(r.spfDom, r.fromDom, r.spfMode())
	ev := map[string]any{"from_domain": r.fromDom, "dkim_aligned": dkimAligned, "spf_aligned": spfAligned}
	if r.dmarcRec != nil && r.dmarcRec.Rec != nil {
		ev["policy"] = string(r.dmarcRec.Rec.Policy)
	}
	c := verdict.Check{ID: "auth.dmarc", Category: verdict.Auth, Evidence: ev, Docs: docsDMARC}
	switch {
	case dkimAligned || spfAligned:
		c.Status, c.Title = verdict.Pass, "DMARC passes"
	case r.fp.Auth["dkim"] == verdict.Skipped && r.spfRes == verdict.Skipped:
		c = skipped("auth.dmarc", verdict.Auth, "DMARC not evaluated", "Neither DKIM nor SPF could be checked.")
	case r.spfRes == verdict.Skipped && !dkimAligned:
		c.Status, c.Title = verdict.Fail, "DMARC does not align through DKIM"
		c.Detail = "SPF was not checked, and no DKIM signature uses the From domain " + r.fromDom + "."
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Set up DKIM with your own domain (" + r.fromDom + ") in your email platform, so messages are signed as you rather than as the platform."}
	default:
		c.Status, c.Title = verdict.Fail, "DMARC does not align"
		c.Detail = "Neither a passing DKIM signature nor a passing SPF check uses the From domain " + r.fromDom + "."
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Set up DKIM with your own domain (" + r.fromDom + ") in your email platform, so messages are signed as you rather than as the platform."}
	}
	r.fp.Auth["dmarc"] = c.Status
	r.add(c)
}

func (r *run) checkAlignment() {
	dkimAligned := false
	for _, d := range r.dkim {
		if d.Result == "pass" && d.Aligned {
			dkimAligned = true
		}
	}
	spfAligned := r.spfRes == verdict.Pass && aligned(r.spfDom, r.fromDom, r.spfMode())
	c := verdict.Check{
		ID: "auth.alignment", Category: verdict.Auth,
		Evidence: map[string]any{
			"from_domain": r.fromDom, "spf_domain": r.spfDom,
			"dkim_mode": string(r.dkimMode()), "spf_mode": string(r.spfMode()),
			"dkim_aligned": dkimAligned, "spf_aligned": spfAligned,
		},
	}
	switch {
	case dkimAligned:
		c.Status, c.Title = verdict.Pass, "DKIM aligns with the From domain"
	case spfAligned:
		c.Status, c.Title = verdict.Warn, "Only SPF aligns with the From domain"
		c.Detail = "SPF alignment breaks when a subscriber forwards the message. DKIM alignment survives it."
		c.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Set up DKIM with your own domain as well."}
	default:
		c.Status, c.Title = verdict.Info, "Nothing aligns with the From domain"
		c.Detail = "See auth.dmarc."
	}
	r.add(c)
}

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
		Evidence: map[string]any{"ip": ip.String(), "ptr": names},
		Fix:      &verdict.Fix{Who: verdict.FixedByProvider, Text: "The sending server needs reverse DNS that resolves back to its own address. Only your email platform can set this."},
	}
	for _, n := range names {
		addrs, err := r.res.LookupIPAddr(r.ctx, strings.TrimSuffix(n, "."))
		if err != nil {
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
