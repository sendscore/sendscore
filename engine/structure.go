package engine

import (
	"fmt"
	"net/mail"
	"strings"

	"github.com/sendscore/sendscore/verdict"
)

// Gmail clips a message whose HTML is larger than about 102 KB and hides
// the rest behind "View entire message", including the footer.
const (
	gmailClipBytes = 102 * 1024
	clipWarnBytes  = 90 * 1024
)

var freeMailboxDomains = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "yahoo.com": true, "ymail.com": true,
	"outlook.com": true, "hotmail.com": true, "live.com": true, "msn.com": true,
	"aol.com": true, "icloud.com": true, "me.com": true, "mac.com": true,
	"proton.me": true, "protonmail.com": true, "gmx.com": true, "mail.com": true,
	"yandex.com": true, "zoho.com": true,
}

func (r *run) structure() {
	m := r.msg

	var mimeEv map[string]any
	if len(m.MIMENotes) > 0 {
		notes := m.MIMENotes
		mimeEv = map[string]any{"notes": notes}
		if len(notes) > 20 {
			mimeEv["notes"] = notes[:20]
			mimeEv["notes_total"] = len(notes)
		}
	}
	switch {
	case m.MIMEErr != nil:
		r.add(verdict.Check{
			ID: "struct.mime", Category: verdict.Structure, Status: verdict.Fail,
			Title: "The MIME structure is malformed", Detail: m.MIMEErr.Error(), Evidence: mimeEv,
			Fix: &verdict.Fix{Who: verdict.FixedByProvider, Text: "Mail clients may show this message wrongly or not at all. Send the raw message to your email platform's support."},
		})
	case len(m.MIMENotes) > 0:
		r.add(verdict.Check{
			ID: "struct.mime", Category: verdict.Structure, Status: verdict.Warn,
			Title:    "The MIME structure has problems that were worked around",
			Detail:   "SendScore could still read the message, but some mail clients may not.",
			Evidence: mimeEv,
			Fix:      &verdict.Fix{Who: verdict.FixedByProvider, Text: "Send the raw message to your email platform's support, so they can fix how it is built."},
		})
	default:
		r.add(verdict.Check{ID: "struct.mime", Category: verdict.Structure, Status: verdict.Pass, Title: "The MIME structure parses cleanly"})
	}

	switch {
	case strings.TrimSpace(m.Text) != "":
		r.add(verdict.Check{ID: "struct.plain_text", Category: verdict.Structure, Status: verdict.Pass, Title: "Has a plain text version"})
	case m.HTML == "":
		r.add(verdict.Check{ID: "struct.plain_text", Category: verdict.Structure, Status: verdict.Warn, Title: "The message has no readable body"})
	default:
		r.add(verdict.Check{
			ID: "struct.plain_text", Category: verdict.Structure, Status: verdict.Warn,
			Title: "No plain text version",
			Fix:   &verdict.Fix{Who: verdict.FixedByYou, Text: "Turn on the plain text version in your email platform, or write one."},
		})
	}

	n := len(m.HTML)
	r.fp.HTMLBytes = n
	size := verdict.Check{ID: "struct.html_size", Category: verdict.Structure, Evidence: map[string]any{"html_bytes": n, "clip_bytes": gmailClipBytes}}
	switch {
	case m.HTML == "":
		size.Status, size.Title = verdict.Info, "No HTML part"
	case n > gmailClipBytes:
		size.Status, size.Title = verdict.Fail, fmt.Sprintf("HTML is %d KB, so Gmail will clip it", n/1024)
		size.Detail = "Gmail hides everything after about 102 KB behind \"View entire message\", including your footer and unsubscribe link."
		size.Fix = &verdict.Fix{Who: verdict.FixedByYou, Text: "Shorten the issue, or remove inline CSS and unused template blocks."}
	case n > clipWarnBytes:
		size.Status, size.Title = verdict.Warn, fmt.Sprintf("HTML is %d KB, close to Gmail's clipping limit", n/1024)
	default:
		size.Status, size.Title = verdict.Pass, fmt.Sprintf("HTML is %d KB", (n+1023)/1024)
	}
	r.add(size)

	var missing []string
	if m.Header.Get("Message-Id") == "" {
		missing = append(missing, "Message-ID")
	}
	if _, err := m.Header.Date(); err != nil {
		missing = append(missing, "Date")
	}
	froms, err := mail.ParseAddressList(m.Header.Get("From"))
	if err != nil || len(froms) != 1 || len(m.all("From")) != 1 {
		missing = append(missing, "a single valid From")
	}
	if len(missing) > 0 {
		r.add(verdict.Check{
			ID: "struct.headers", Category: verdict.Structure, Status: verdict.Fail,
			Title:    "Missing or malformed: " + strings.Join(missing, ", "),
			Evidence: map[string]any{"missing": missing},
			Fix:      &verdict.Fix{Who: verdict.FixedByProvider, Text: "These headers are required by RFC 5322; your email platform should set them."},
		})
	} else {
		r.add(verdict.Check{ID: "struct.headers", Category: verdict.Structure, Status: verdict.Pass, Title: "Message-ID, Date, and From are present"})
	}

	if freeMailboxDomains[r.fromDom] {
		r.add(verdict.Check{
			ID: "struct.from_domain", Category: verdict.Structure, Status: verdict.Fail,
			Title:    "Sent from a free mailbox address (" + r.fromDom + ")",
			Detail:   r.fromDom + " belongs to a mailbox provider, not to you, so mail your platform sends as this address cannot align with its DMARC record. Gmail and Yahoo require bulk mail to align, and several of these providers publish a quarantine or reject policy.",
			Evidence: map[string]any{"from_domain": r.fromDom},
			Fix:      &verdict.Fix{Who: verdict.FixedByYou, Text: "Send from an address on a domain you own."},
		})
	} else if r.fromDom != "" {
		r.add(verdict.Check{ID: "struct.from_domain", Category: verdict.Structure, Status: verdict.Pass, Title: "Sent from your own domain (" + r.fromDom + ")"})
	} else {
		r.add(skipped("struct.from_domain", verdict.Structure, "From domain not checked", "The From header has no address with a domain to check."))
	}
}
