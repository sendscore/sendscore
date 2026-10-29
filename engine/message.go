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

	"golang.org/x/net/html/charset"
)

// maxParts bounds the MIME walk, so a hostile message cannot make the engine
// recurse or allocate without limit.
const (
	maxParts = 64
	maxDepth = 8
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
	// MIMEErr is set when the body could not be walked cleanly. The headers
	// are still usable.
	MIMEErr error
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

	parts := 0
	m.MIMEErr = m.walk(textproto.MIMEHeader(msg.Header), msg.Body, 0, &parts)
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

func (m *message) walk(h textproto.MIMEHeader, body io.Reader, depth int, parts *int) error {
	*parts++
	if *parts > maxParts {
		return errors.New("too many MIME parts")
	}
	if depth > maxDepth {
		return errors.New("MIME parts nested too deeply")
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		ct = "text/plain; charset=us-ascii"
	}
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return fmt.Errorf("bad Content-Type %q: %w", ct, err)
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return fmt.Errorf("%s has no boundary", mediaType)
		}
		mr := multipart.NewReader(body, boundary)
		for {
			p, err := mr.NextRawPart()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return fmt.Errorf("reading %s: %w", mediaType, err)
			}
			if err := m.walk(p.Header, p, depth+1, parts); err != nil {
				return err
			}
		}
	}

	if disp := h.Get("Content-Disposition"); strings.HasPrefix(strings.ToLower(disp), "attachment") {
		name := mediaType
		if _, dp, err := mime.ParseMediaType(disp); err == nil && dp["filename"] != "" {
			name = dp["filename"]
		}
		m.Attachments = append(m.Attachments, name)
		return nil
	}
	if mediaType != "text/html" && mediaType != "text/plain" {
		return nil
	}
	decoded, err := decodeBody(body, h.Get("Content-Transfer-Encoding"), params["charset"])
	if err != nil {
		return fmt.Errorf("decoding %s: %w", mediaType, err)
	}
	// The first part of each kind is the one a mail client shows.
	if mediaType == "text/html" && m.HTML == "" {
		m.HTML = decoded
	} else if mediaType == "text/plain" && m.Text == "" {
		m.Text = decoded
	}
	return nil
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
// "Name <a@b.com>" or "<a@b.com>".
func addrDomain(s string) string {
	s = strings.TrimSpace(s)
	if a, err := mail.ParseAddress(s); err == nil {
		s = a.Address
	}
	s = strings.Trim(s, "<>")
	_, d, ok := strings.Cut(s, "@")
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(d, "."))
}
