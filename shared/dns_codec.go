package shared

import (
	"encoding/base32"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

const (
	maxLabelLength   = 63
	maxTXTLength     = 255
	MaxDNSWireLength = 255
)

var (
	b32Encoder       *base32.Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	domainLabelCache sync.Map
)

// EncodeQuery converts a Message into a DNS query whose question name carries the payload.
// The domain parameter is appended to the encoded name.
// Returns an error if the resulting name would exceed DNS length limits.
func EncodeQuery(msg Message, domain string) (encoded *dns.Msg, err error) {
	var wire []byte
	if wire, err = msg.MarshalBinary(); err != nil {
		return
	}

	var (
		encodedStr string   = b32Encoder.EncodeToString(wire)
		labels     []string = chunkString(encodedStr, maxLabelLength)
		name       string   = strings.Join(labels, ".")
	)

	if domain = normalizeDomain(domain); domain != "" {
		name = name + "." + domain
	}

	var wireLen int
	if wireLen, err = wireNameLength(labels, domain); err != nil {
		return
	}

	if wireLen > MaxDNSWireLength {
		err = ErrNameTooLong
		return
	}

	encoded = new(dns.Msg)
	encoded.SetQuestion(ensureTrailingDot(name), dns.TypeTXT)
	return
}

// DecodeQuery reverses EncodeQuery, pulling the message payload out of the question name.
// The domain parameter is used to verify and strip the domain suffix from the name.
// Returns an error if the name is malformed or the domain does not match.
func DecodeQuery(req *dns.Msg, domain string) (msg Message, err error) {
	if req == nil || len(req.Question) == 0 {
		err = fmt.Errorf("missing question")
		return
	}

	var name string = strings.TrimSuffix(req.Question[0].Name, ".")

	if domain = normalizeDomain(domain); domain != "" {
		if !strings.EqualFold(name, domain) && !strings.HasSuffix(name, "."+domain) {
			err = fmt.Errorf("unexpected domain %q", name)
			return
		}

		if len(name) > len(domain) {
			name = strings.TrimSuffix(name[:len(name)-(len(domain))], ".")
		} else {
			name = ""
		}
	}

	if name == "" {
		err = fmt.Errorf("no encoded labels")
		return
	}

	var raw string = strings.ReplaceAll(name, ".", "")
	var wire []byte
	if wire, err = b32Encoder.DecodeString(raw); err != nil {
		err = fmt.Errorf("decode base32: %w", err)
		return
	}

	msg, err = UnmarshalMessage(wire)
	return
}

// EncodeTXTResponse places the message payload into a TXT record response.
// The response is based on the provided request message.
// Returns an error if the message cannot be encoded.
func EncodeTXTResponse(msg Message, req *dns.Msg) (encoded *dns.Msg, err error) {
	var wire []byte
	if wire, err = msg.MarshalBinary(); err != nil {
		return
	}

	var encodedStr string = b32Encoder.EncodeToString(wire)
	var chunks []string = chunkString(encodedStr, maxTXTLength)

	encoded = new(dns.Msg)
	encoded.SetReply(req)
	encoded.Authoritative = true
	encoded.Answer = append(encoded.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Txt: chunks,
	})

	return
}

// DecodeTXTResponse extracts a Message from the first TXT answer, if present.
// Returns an error if the response is malformed or missing.
func DecodeTXTResponse(resp *dns.Msg) (msg Message, err error) {
	if resp == nil || len(resp.Answer) == 0 {
		err = fmt.Errorf("missing answer")
		return
	}

	var (
		txt *dns.TXT
		ok  bool
	)

	if txt, ok = resp.Answer[0].(*dns.TXT); !ok {
		err = fmt.Errorf("unexpected answer type")
		return
	}

	var (
		raw  string = strings.Join(txt.Txt, "")
		wire []byte
	)

	if wire, err = b32Encoder.DecodeString(raw); err != nil {
		err = fmt.Errorf("decode base32: %w", err)
		return
	}

	msg, err = UnmarshalMessage(wire)
	return
}

// chunkString splits a string into chunks of the specified size.
// The last chunk may be smaller than the specified size.
func chunkString(s string, size int) (parts []string) {
	if size <= 0 {
		parts = nil
		return
	}

	parts = make([]string, 0, (len(s)+size-1)/size)
	for len(s) > 0 {
		if len(s) <= size {
			parts = append(parts, s)
			break
		}
		parts = append(parts, s[:size])
		s = s[size:]
	}

	return
}

// normalizeDomain trims leading and trailing dots from a domain name.
func normalizeDomain(domain string) (norm string) {
	norm = strings.Trim(strings.TrimSuffix(domain, "."), ".")
	return
}

// ensureTrailingDot adds a trailing dot to a domain name if not already present.
func ensureTrailingDot(name string) (ensured string) {
	ensured = name
	if !strings.HasSuffix(name, ".") {
		ensured = name + "."
	}

	return
}

// wireNameLength returns the number of bytes required to encode the name on the wire.
// payloadLabels are the labels carrying the payload, domain is the appended domain.
// Returns an error if any label exceeds the maximum length.
func wireNameLength(payloadLabels []string, domain string) (lenWritten int, err error) {
	var domainLabels, domainLen int
	if domainLabels, domainLen, err = domainLabelInfo(domain); err != nil {
		return
	}

	var totalLabelBytes int
	for _, l := range payloadLabels {
		if len(l) == 0 || len(l) > maxLabelLength {
			err = ErrNameTooLong
			return
		}
		totalLabelBytes += len(l)
	}

	var labelCount int = len(payloadLabels) + domainLabels
	lenWritten = totalLabelBytes + domainLen + labelCount + 1 // +1 for root label
	return
}

// domainLabelInfo returns the number of labels and their total length for a given domain.
// Returns an error if any label exceeds the maximum length.
func domainLabelInfo(domain string) (count int, totalLen int, err error) {
	if domain == "" {
		return
	}

	var (
		v  any
		ok bool
	)

	if v, ok = domainLabelCache.Load(domain); ok {
		var info = v.(struct{ c, l int })
		count = info.c
		totalLen = info.l
		return
	}

	var parts []string = strings.Split(domain, ".")
	for _, p := range parts {
		if p == "" || len(p) > maxLabelLength {
			err = ErrNameTooLong
			return
		}
		count++
		totalLen += len(p)
	}

	domainLabelCache.Store(domain, struct{ c, l int }{count, totalLen})
	return
}
