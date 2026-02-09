package dns

import (
	"encoding/binary"
	"net"
	"strings"
)

// DNS record type A
const DNS_TYPE_A = 1

// DNS record type AAAA
const DNS_TYPE_AAAA = 28

// DNS class IN
const DNS_CLASS_IN = 1

// ParsedDnsQuestion is the first-question metadata extracted from a DNS query
//
// Name is the question name in presentation format
// Type is the question type
// Class is the question class
type ParsedDnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// ParsedDnsQuery is a minimal DNS query representation suitable for generating synthetic answers
//
// QuestionSection contains the raw wire bytes of the *first* question (for echoing in replies)
// FirstQuestion is the decoded first question
type ParsedDnsQuery struct {
	ID              uint16
	Flags           uint16
	QuestionSection []byte
	FirstQuestion   ParsedDnsQuestion
}

type SyntheticDnsResponseOptions struct {
	IPv4       string
	IPv6       string
	TtlSeconds uint32
}

// IsProbablyDnsPacket returns true if the payload is large enough to contain a DNS header
func IsProbablyDnsPacket(packet []byte) bool {
	return len(packet) >= 12
}

func parseName(packet []byte, offset int) (name string, next int, ok bool) {
	labels := make([]string, 0, 8)
	off := offset
	seen := 0

	for {
		if off >= len(packet) {
			return "", 0, false
		}
		l := int(packet[off])
		off++

		if l == 0 {
			break
		}

		// compression pointer is explicitly rejected for queries
		if (l & 0xc0) == 0xc0 {
			return "", 0, false
		}
		if l > 63 {
			return "", 0, false
		}
		if off+l > len(packet) {
			return "", 0, false
		}
		labels = append(labels, string(packet[off:off+l]))
		off += l

		seen++
		if seen > 128 {
			return "", 0, false
		}
	}

	// Normalize to lower-case.
	out := strings.ToLower(strings.Join(filterNonEmpty(labels), "."))
	return out, off, true
}

func filterNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ParseDnsQuery parses a DNS query packet and returns a minimal representation.
//
// This is intentionally conservative and rejects compression pointers in the question section.
func ParseDnsQuery(packet []byte) *ParsedDnsQuery {
	if len(packet) < 12 {
		return nil
	}

	id := binary.BigEndian.Uint16(packet[0:2])
	flags := binary.BigEndian.Uint16(packet[2:4])
	qdcount := binary.BigEndian.Uint16(packet[4:6])
	ancount := binary.BigEndian.Uint16(packet[6:8])
	nscount := binary.BigEndian.Uint16(packet[8:10])

	qr := (flags & 0x8000) != 0
	opcode := (flags >> 11) & 0x0f
	if qr {
		return nil
	}
	if opcode != 0 {
		return nil
	}
	if ancount != 0 || nscount != 0 {
		return nil
	}

	if qdcount < 1 {
		return nil
	}
	if qdcount > 16 {
		return nil
	}

	off := 12
	var first *ParsedDnsQuestion
	firstEnd := -1

	for i := 0; i < int(qdcount); i++ {
		qname, next, ok := parseName(packet, off)
		if !ok {
			return nil
		}
		off = next
		if off+4 > len(packet) {
			return nil
		}
		qt := binary.BigEndian.Uint16(packet[off : off+2])
		qc := binary.BigEndian.Uint16(packet[off+2 : off+4])
		off += 4

		if first == nil {
			first = &ParsedDnsQuestion{Name: qname, Type: qt, Class: qc}
			firstEnd = off
		}
	}

	if first == nil || firstEnd < 0 {
		return nil
	}

	qsec := make([]byte, firstEnd-12)
	copy(qsec, packet[12:firstEnd])

	return &ParsedDnsQuery{
		ID:              id,
		Flags:           flags,
		QuestionSection: qsec,
		FirstQuestion:   *first,
	}
}

func parseIPv4(ip string) []byte {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	v4 := parsed.To4()
	if v4 == nil {
		return nil
	}
	out := make([]byte, 4)
	copy(out, v4)
	return out
}

func parseIPv6(ip string) []byte {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	v16 := parsed.To16()
	if v16 == nil {
		return nil
	}
	// Ensure it's actually an IPv6 literal (not v4). The TS impl requires net.isIP(ip)===6.
	if parsed.To4() != nil {
		// This is an IPv4 address, not suitable for AAAA responses.
		return nil
	}
	out := make([]byte, 16)
	copy(out, v16)
	return out
}

// BuildSyntheticDnsResponse builds a minimal synthetic DNS response for the query.
//
// Only the *first* question is answered and echoed. The response uses QDCOUNT=1.
func BuildSyntheticDnsResponse(query *ParsedDnsQuery, options SyntheticDnsResponseOptions) []byte {
	// Copy RD bit from request, set QR + RA.
	rd := query.Flags & 0x0100
	flags := uint16(0x8000) | rd | 0x0080

	question := query.FirstQuestion

	var answerType uint16
	var rdata []byte

	if question.Class == DNS_CLASS_IN {
		switch question.Type {
		case DNS_TYPE_A:
			answerType = DNS_TYPE_A
			rdata = parseIPv4(options.IPv4)
		case DNS_TYPE_AAAA:
			answerType = DNS_TYPE_AAAA
			rdata = parseIPv6(options.IPv6)
		}
	}

	hasAnswer := answerType != 0 && rdata != nil

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], query.ID)
	binary.BigEndian.PutUint16(header[2:4], flags)
	binary.BigEndian.PutUint16(header[4:6], 1) // qdcount
	if hasAnswer {
		binary.BigEndian.PutUint16(header[6:8], 1)
	} else {
		binary.BigEndian.PutUint16(header[6:8], 0)
	}
	binary.BigEndian.PutUint16(header[8:10], 0)
	binary.BigEndian.PutUint16(header[10:12], 0)

	sections := make([][]byte, 0, 4)
	sections = append(sections, header, query.QuestionSection)

	if hasAnswer {
		rr := make([]byte, 12) // name ptr + type + class + ttl + rdlength
		binary.BigEndian.PutUint16(rr[0:2], 0xc00c)
		binary.BigEndian.PutUint16(rr[2:4], answerType)
		binary.BigEndian.PutUint16(rr[4:6], DNS_CLASS_IN)
		binary.BigEndian.PutUint32(rr[6:10], options.TtlSeconds)
		binary.BigEndian.PutUint16(rr[10:12], uint16(len(rdata)))
		sections = append(sections, rr, rdata)
	}

	// Flatten.
	outLen := 0
	for _, s := range sections {
		outLen += len(s)
	}
	out := make([]byte, 0, outLen)
	for _, s := range sections {
		out = append(out, s...)
	}
	return out
}
