package virtio

import "testing"

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := Envelope{V: 1, T: "exec_output", ID: 42, P: map[string]any{"stream": "stdout", "data": []byte("hello")}}
	payload, err := EncodePayload(in)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}

	out, err := DecodePayload(payload)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if out.V != 1 || out.T != in.T || out.ID != in.ID {
		t.Fatalf("envelope mismatch: %+v", out)
	}
	if out.P["stream"].(string) != "stdout" {
		t.Fatalf("stream mismatch")
	}
	data, ok := out.P["data"].([]byte)
	if !ok {
		t.Fatalf("expected data to decode as []byte, got %T", out.P["data"])
	}
	if string(data) != "hello" {
		t.Fatalf("data mismatch: %q", string(data))
	}
}

func TestDecodeNormalizesNestedMaps(t *testing.T) {
	in := Envelope{V: 1, T: "fs_request", ID: 7, P: map[string]any{"op": "lookup", "req": map[string]any{"parent_ino": uint64(1), "name": "etc"}}}
	payload, err := EncodePayload(in)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}

	out, err := DecodePayload(payload)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	reqAny := out.P["req"]
	m, ok := reqAny.(map[string]any)
	if !ok {
		t.Fatalf("expected req to be map[string]any, got %T", reqAny)
	}
	if m["name"].(string) != "etc" {
		t.Fatalf("name mismatch")
	}
}
