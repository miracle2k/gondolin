package virtio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

const (
	// MaxFrame is the maximum allowed CBOR payload size in `bytes`
	MaxFrame = 4 * 1024 * 1024
)

// Envelope is the standard message envelope used by the guest↔host virtio-serial protocol.
//
// CBOR encoding matches guest/src/shared/protocol.zig and host/src/virtio-protocol.ts.
//
// Keys:
//   - v: protocol version (currently 1)
//   - t: message type
//   - id: correlation id
//   - p: payload map
//
// Note: For binary payload fields (e.g. exec_output.p.data), p values will be decoded as []byte.
type Envelope struct {
	V  uint32         `cbor:"v"`
	T  string         `cbor:"t"`
	ID uint32         `cbor:"id"`
	P  map[string]any `cbor:"p"`
}

// EncodePayload encodes a message envelope as a CBOR payload (no length prefix).
func EncodePayload(msg Envelope) ([]byte, error) {
	if msg.V == 0 {
		msg.V = 1
	}
	return cbor.Marshal(msg)
}

// DecodePayload decodes a CBOR payload into an envelope.
func DecodePayload(payload []byte) (Envelope, error) {
	var env Envelope
	if err := cbor.Unmarshal(payload, &env); err != nil {
		return Envelope{}, err
	}
	if env.P == nil {
		env.P = map[string]any{}
	} else {
		env.P = normalize(env.P).(map[string]any)
	}
	return env, nil
}

func normalize(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, entry := range v {
			out[k] = normalize(entry)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for k, entry := range v {
			out[fmt.Sprint(k)] = normalize(entry)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, entry := range v {
			out[i] = normalize(entry)
		}
		return out
	default:
		return value
	}
}

// EncodeFrame encodes an envelope as a length-prefixed frame.
func EncodeFrame(msg Envelope) ([]byte, error) {
	payload, err := EncodePayload(msg)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxFrame {
		return nil, errors.New("frame too large")
	}
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(payload)))
	copy(out[4:], payload)
	return out, nil
}

// ReadFrame reads a single length-prefixed frame from r.
func ReadFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > MaxFrame {
		return nil, errors.New("frame too large")
	}
	payload := make([]byte, n)
	if n == 0 {
		return payload, nil
	}
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// WriteFrame writes a single length-prefixed frame to w.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrame {
		return errors.New("frame too large")
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}
