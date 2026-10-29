// Package verdict holds the report SendScore returns for one received
// message. It is the JSON contract shared by the CLI, the hosted app, the API,
// and the MCP tools, so a field is never renamed or repurposed within a
// schema version: add a field, or bump Schema.
package verdict

import "time"

// Schema names this version of the JSON shape.
const Schema = "sendscore.verdict/v1"

// Note is attached to every verdict. Receipt at SendScore is evidence about
// the message, never about where it landed at a mailbox provider.
const Note = "Receipt at SendScore does not prove inbox placement at Gmail or any other provider."

// Status is the outcome of one check.
type Status string

const (
	Pass    Status = "pass"
	Warn    Status = "warn"
	Fail    Status = "fail"
	Info    Status = "info"
	Skipped Status = "skipped"
)

// Category groups checks. Authentication and unsubscribe failures block
// ready_to_send by default; the rest are reported without blocking.
type Category string

const (
	Auth      Category = "auth"
	Unsub     Category = "unsub"
	Structure Category = "struct"
	Content   Category = "content"
	Delivery  Category = "delivery"
	Changes   Category = "changes"
)

// Who fixes a failure: the publisher (a DNS record, a template) or the
// sending platform (its signing setup, its servers).
const (
	FixedByYou      = "you"
	FixedByProvider = "provider"
)

// Verdict is the full report for one message.
type Verdict struct {
	Schema      string       `json:"schema"`
	ID          string       `json:"id,omitempty"`
	Message     Message      `json:"message"`
	Publication string       `json:"publication,omitempty"`
	Verdict     Status       `json:"verdict"`
	ReadyToSend bool         `json:"ready_to_send"`
	Summary     string       `json:"summary"`
	TopFixes    []TopFix     `json:"top_fixes"`
	Checks      []Check      `json:"checks"`
	Changes     []Change     `json:"changes"`
	Fingerprint *Fingerprint `json:"fingerprint,omitempty"`
	// Explanation is the optional AI write-up. Nothing else in the verdict
	// depends on it, and the engine never fills it.
	Explanation *string `json:"explanation"`
	Note        string  `json:"note"`
}

// Message identifies what was checked.
type Message struct {
	ReceivedAt time.Time `json:"received_at"`
	From       string    `json:"from"`
	Subject    string    `json:"subject"`
	MessageID  string    `json:"message_id"`
	SizeBytes  int       `json:"size_bytes"`
}

// Check is one rule applied to the message, with the evidence it looked at.
type Check struct {
	ID       string         `json:"id"`
	Category Category       `json:"category"`
	Status   Status         `json:"status"`
	Title    string         `json:"title"`
	Detail   string         `json:"detail,omitempty"`
	Evidence map[string]any `json:"evidence,omitempty"`
	Fix      *Fix           `json:"fix,omitempty"`
	Docs     string         `json:"docs,omitempty"`
	// Reason says why a check was skipped.
	Reason string `json:"reason,omitempty"`
}

// Fix says what to change and who can change it.
type Fix struct {
	Who  string `json:"who"`
	Text string `json:"text"`
}

// TopFix is one of the (at most three) fixes to make first.
type TopFix struct {
	Check string `json:"check"`
	Who   string `json:"who"`
	Fix   string `json:"fix"`
}

// Change is one difference from the previous issue of the same publication.
type Change struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
	// Worsened names the check this change made worse, if any.
	Worsened string `json:"worsened,omitempty"`
}

// Fingerprint is what the comparison looks at. It is stored with every
// verdict so the next issue can be compared without the previous message.
type Fingerprint struct {
	DKIMDomains      []string          `json:"dkim_domains"`
	DKIMSelectors    []string          `json:"dkim_selectors"`
	ReturnPathDomain string            `json:"return_path_domain"`
	RemoteIP         string            `json:"remote_ip,omitempty"`
	PTR              string            `json:"ptr,omitempty"`
	ListUnsubscribe  bool              `json:"list_unsubscribe"`
	OneClick         bool              `json:"one_click"`
	LinkHosts        []string          `json:"link_hosts"`
	HTMLBytes        int               `json:"html_bytes"`
	Links            int               `json:"links"`
	Images           int               `json:"images"`
	Auth             map[string]Status `json:"auth"`
}
