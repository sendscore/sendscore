package engine

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"unicode"

	"golang.org/x/net/html/charset"
)

// maxParts bounds the MIME walk, so a hostile message cannot make the engine
// recurse or allocate without limit. maxPartHeaders bounds the header
// fields of one part, which real mail keeps to a handful.
const (
	maxParts       = 64
	maxDepth       = 8
	maxPartHeaders = 100
)

// header is one raw header field, in message order, unfolded.
type header struct {
	Name  string
	Value string
}

// message is the parsed form the checks read.
type message struct {
	Raw     []byte
	Headers []header
	Header  mail.Header
	HTML    string
	Text    string
	// MIMEErr is set when some part of the body could not be read. It joins
	// one error per bad part; the walk goes on past each, so the parts after
	// it are still read. The headers are still usable.
	MIMEErr error
	// MIMENotes lists problems that were worked around without losing a
	// part's content, such as a malformed Content-Type parameter, or that
	// stopped the walk early without the message being malformed, such as
	// more parts than are read.
	MIMENotes []string
	// Attachments names the parts sent as attachments.
	Attachments []string
}

var wordDecoder = &mime.WordDecoder{CharsetReader: charset.NewReaderLabel}

func parseMessage(raw []byte) (*message, error) {
	m := &message{Raw: raw}
	hdrs, err := rawHeaders(raw)
	if err != nil {
		return nil, err
	}
	m.Headers = hdrs

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("not an email message: %w", err)
	}
	m.Header = msg.Header

	w := &walker{m: m}
	w.walk(textproto.MIMEHeader(msg.Header), msg.Body, 0)
	m.MIMEErr = errors.Join(w.errs...)
	return m, nil
}

// get returns the decoded value of the first header with this name.
func (m *message) get(name string) string {
	v := m.Header.Get(name)
	if d, err := wordDecoder.DecodeHeader(v); err == nil {
		return d
	}
	return v
}

// all returns every raw value of the header, in order.
func (m *message) all(name string) []string {
	var out []string
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}

// walker carries one MIME walk. A problem in one part is recorded and the
// walk moves on, so one bad part does not hide the rest of the message.
type walker struct {
	m     *message
	parts int
	errs  []error
	// full is set once maxParts parts have been read; the rest are left.
	full bool
}

func (w *walker) note(format string, args ...any) {
	w.m.MIMENotes = append(w.m.MIMENotes, fmt.Sprintf(format, args...))
}

func (w *walker) walk(h textproto.MIMEHeader, body io.Reader, depth int) {
	m := w.m
	if w.full {
		return
	}
	if w.parts >= maxParts {
		w.full = true
		w.note("The message has more than %d MIME parts, and only the first %d were read.", maxParts, maxParts)
		return
	}
	w.parts++
	if depth > maxDepth {
		w.errs = append(w.errs, fmt.Errorf("MIME parts nested more than %d deep", maxDepth))
		return
	}
	if len(h) > maxPartHeaders {
		w.errs = append(w.errs, fmt.Errorf("a MIME part has more than %d header fields", maxPartHeaders))
		return
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		ct = "text/plain; charset=us-ascii"
	}
	mediaType, params, err := mime.ParseMediaType(ct)
	if errors.Is(err, mime.ErrInvalidMediaParameter) {
		// The media type is still good. Keep the parameters that parse.
		params = lenientParams(ct)
		w.note("The Content-Type %q has a malformed parameter, which was ignored.", truncate(ct, 80))
	} else if err != nil {
		w.errs = append(w.errs, fmt.Errorf("bad Content-Type %q: %w", truncate(ct, 80), err))
		return
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			w.errs = append(w.errs, fmt.Errorf("%s has no boundary", mediaType))
			return
		}
		mr := multipart.NewReader(body, boundary)
		for !w.full {
			p, err := mr.NextRawPart()
			if err == io.EOF {
				return
			}
			if err != nil {
				// The reader cannot find the next boundary, so nothing
				// more of this multipart can be read.
				w.errs = append(w.errs, fmt.Errorf("reading %s: %w", mediaType, err))
				return
			}
			w.walk(p.Header, p, depth+1)
		}
		return
	}

	if disp := h.Get("Content-Disposition"); strings.HasPrefix(strings.ToLower(disp), "attachment") {
		name := mediaType
		if _, dp, err := mime.ParseMediaType(disp); err == nil && dp["filename"] != "" {
			name = dp["filename"]
		}
		m.Attachments = append(m.Attachments, name)
		return
	}
	if mediaType != "text/html" && mediaType != "text/plain" {
		return
	}
	// A part that fails to decode partway keeps what decoded, which is
	// what a lenient mail client shows.
	decoded, err := decodeBody(body, h.Get("Content-Transfer-Encoding"), params["charset"])
	if err != nil {
		w.errs = append(w.errs, fmt.Errorf("decoding %s: %w", mediaType, err))
	}
	// The first part of each kind is the one a mail client shows.
	if mediaType == "text/html" && m.HTML == "" {
		m.HTML = decoded
	} else if mediaType == "text/plain" && m.Text == "" {
		m.Text = decoded
	}
}

// lenientParams reads the "; key=value" parameters of a header value one
// at a time, keeping those that parse, for a value mime.ParseMediaType
// rejects as a whole.
func lenientParams(v string) map[string]string {
	out := map[string]string{}
	_, rest, _ := strings.Cut(v, ";")
	for _, part := range strings.Split(rest, ";") {
		k, val, ok := strings.Cut(part, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if !ok || k == "" || strings.ContainsAny(k, " \t\"()<>@,:/[]?") {
			continue
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		if _, dup := out[k]; !dup && val != "" {
			out[k] = val
		}
	}
	return out
}

func decodeBody(r io.Reader, cte, cs string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, &stripSpace{r: r})
	}
	if cs != "" && !strings.EqualFold(cs, "utf-8") && !strings.EqualFold(cs, "us-ascii") {
		cr, err := charset.NewReaderLabel(cs, r)
		if err == nil {
			r = cr
		}
	}
	b, err := io.ReadAll(io.LimitReader(r, 16<<20))
	return string(b), err
}

// stripSpace drops the line breaks base64 bodies carry, which the standard
// decoder does not accept.
type stripSpace struct{ r io.Reader }

func (s *stripSpace) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	j := 0
	for i := 0; i < n; i++ {
		switch p[i] {
		case '\r', '\n', ' ', '\t':
		default:
			p[j] = p[i]
			j++
		}
	}
	if j == 0 && n > 0 && err == nil {
		return s.Read(p)
	}
	return j, err
}

// Limits on the header block. Real mail carries a few dozen headers in a
// few kilobytes; these stop a hostile message from costing more than that.
const (
	maxHeaderBytes = 1 << 20
	maxHeaders     = 1000
)

// rawHeaders reads the header block in order, unfolding continuation lines.
// The DKIM check needs the order, which mail.Header does not keep. Each
// header's lines are collected and joined once, so a header folded across
// many lines costs linear time.
func rawHeaders(raw []byte) ([]header, error) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var out []header
	var parts []string
	flush := func() {
		if len(out) > 0 && len(parts) > 0 {
			out[len(out)-1].Value = strings.Join(parts, " ")
		}
		parts = parts[:0]
	}
	size := 0
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			flush()
			return out, nil
		}
		size += len(line) + 2
		if size > maxHeaderBytes {
			return nil, fmt.Errorf("not an email message: the header block is larger than %d KB", maxHeaderBytes>>10)
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(out) == 0 {
				return nil, errors.New("not an email message: starts with a continuation line")
			}
			parts = append(parts, strings.TrimSpace(line))
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("not an email message: bad header line %q", truncate(line, 60))
		}
		flush()
		if len(out) >= maxHeaders {
			return nil, fmt.Errorf("not an email message: more than %d header fields", maxHeaders)
		}
		out = append(out, header{Name: strings.TrimSpace(name)})
		parts = append(parts, strings.TrimSpace(value))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return out, nil
}

// tagList parses a DKIM style "k=v; k=v" list.
func tagList(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = strings.Join(strings.Fields(v), "")
	}
	return out
}

// truncate shortens s to n characters, never splitting one.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// addrDomain returns the lowercased domain of an address such as
// "Name <a@b.com>" or "<a@b.com>". For a list of addresses it uses the
// first. A value that does not parse gives a domain only when it is plainly
// one bare address, never a domain cut out of a longer string.
func addrDomain(s string) string {
	s = strings.TrimSpace(s)
	p := mail.AddressParser{WordDecoder: wordDecoder}
	if list, err := p.ParseList(s); err == nil && len(list) > 0 {
		s = list[0].Address
	} else {
		s = strings.TrimSuffix(strings.TrimPrefix(s, "<"), ">")
		if strings.ContainsAny(s, " \t,;<>\"()") || strings.Count(s, "@") != 1 {
			return ""
		}
	}
	_, d, ok := strings.Cut(s, "@")
	if !ok {
		return ""
	}
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	if strings.ContainsFunc(d, unicode.IsSpace) || strings.ContainsAny(d, "@<>,;\"()[]\\") {
		return ""
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return ""
		}
	}
	return d
}
