package dns

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func buildQuestionA(name string) []byte {
	labels := bytes.Split([]byte(name), []byte("."))
	qnameParts := make([]byte, 0, 64)
	for _, label := range labels {
		if len(label) == 0 {
			continue
		}
		qnameParts = append(qnameParts, byte(len(label)))
		qnameParts = append(qnameParts, label...)
	}
	qnameParts = append(qnameParts, 0)

	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], DNS_TYPE_A)
	binary.BigEndian.PutUint16(tail[2:4], DNS_CLASS_IN)

	return append(qnameParts, tail...)
}

func buildQueryA(name string, id uint16) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(header[6:8], 0)
	binary.BigEndian.PutUint16(header[8:10], 0)
	binary.BigEndian.PutUint16(header[10:12], 0)

	return append(header, buildQuestionA(name)...)
}

func TestParseDnsQueryAndBuildSyntheticResponseA(t *testing.T) {
	queryBuf := buildQueryA("example.com", 0xabcd)
	q := ParseDnsQuery(queryBuf)
	if q == nil {
		t.Fatalf("expected query")
	}
	if q.ID != 0xabcd {
		t.Fatalf("id mismatch: got %x", q.ID)
	}
	if q.FirstQuestion.Name != "example.com" {
		t.Fatalf("name mismatch: %q", q.FirstQuestion.Name)
	}

	resp := BuildSyntheticDnsResponse(q, SyntheticDnsResponseOptions{
		IPv4:       "192.0.2.1",
		IPv6:       "2001:db8::1",
		TtlSeconds: 60,
	})

	if binary.BigEndian.Uint16(resp[0:2]) != 0xabcd {
		t.Fatalf("response id mismatch")
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if (flags & 0x8000) == 0 {
		t.Fatalf("expected QR bit")
	}
	if binary.BigEndian.Uint16(resp[4:6]) != 1 {
		t.Fatalf("expected QDCOUNT=1")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatalf("expected ANCOUNT=1")
	}

	// A RDATA is last 4 bytes
	if !bytes.Equal(resp[len(resp)-4:], []byte{192, 0, 2, 1}) {
		t.Fatalf("unexpected rdata: %v", resp[len(resp)-4:])
	}
}

func TestSyntheticResponseOnlyEchoesFirstQuestion(t *testing.T) {
	q1 := buildQuestionA("example.com")
	q2 := buildQuestionA("example.net")

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xbeef)
	binary.BigEndian.PutUint16(header[2:4], 0x0100)
	binary.BigEndian.PutUint16(header[4:6], 2) // QDCOUNT

	queryBuf := append(append(header, q1...), q2...)
	q := ParseDnsQuery(queryBuf)
	if q == nil {
		t.Fatalf("expected query")
	}
	if !bytes.Equal(q.QuestionSection, q1) {
		t.Fatalf("expected questionSection to equal first question bytes")
	}

	resp := BuildSyntheticDnsResponse(q, SyntheticDnsResponseOptions{
		IPv4:       "192.0.2.1",
		IPv6:       "2001:db8::1",
		TtlSeconds: 60,
	})
	if binary.BigEndian.Uint16(resp[4:6]) != 1 {
		t.Fatalf("expected QDCOUNT=1")
	}
	if !bytes.Equal(resp[12:12+len(q1)], q1) {
		t.Fatalf("expected echoed question bytes")
	}
	if bytes.Contains(resp, []byte("example.net")) {
		t.Fatalf("did not expect response to contain second question")
	}
}
