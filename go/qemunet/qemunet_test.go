package qemunet

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func makeBackend(t *testing.T, opts QemuNetworkOptions) *QemuNetworkBackend {
	t.Helper()
	if opts.MaxHttpBodyBytes == 0 {
		opts.MaxHttpBodyBytes = 64 * 1024 * 1024
	}
	backend, err := NewQemuNetworkBackend(opts)
	if err != nil {
		t.Fatalf("NewQemuNetworkBackend: %v", err)
	}
	// Provide a default fetch that must not be called in parsing tests.
	if backend.fetch == nil {
		backend.fetch = func(_ string, _ HttpFetchInit) (*HttpFetchResponse, error) {
			return nil, NewHttpRequestBlockedError("fetch not configured", 500, "Internal")
		}
	}
	return backend
}

func TestTrustedDnsModeRequiresIpv4Resolvers(t *testing.T) {
	_, err := NewQemuNetworkBackend(QemuNetworkOptions{Dns: DnsOptions{Mode: DnsModeTrusted, TrustedServers: []string{"::1"}}})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "requires") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseHttpRequestContentLengthAndRemaining(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 1024})
	buf := []byte(
		"POST /path HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Content-Length: 5\r\n" +
			"X-Test: a\r\n" +
			"X-Test: b\r\n" +
			"\r\n" +
			"hello" +
			"EXTRA")

	parsed, err := backend.parseHttpRequest(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed == nil {
		t.Fatalf("expected parsed")
	}
	if parsed.Request.Method != "POST" {
		t.Fatalf("method mismatch")
	}
	if parsed.Request.Target != "/path" {
		t.Fatalf("target mismatch")
	}
	if parsed.Request.Version != "HTTP/1.1" {
		t.Fatalf("version mismatch")
	}
	if parsed.Request.Headers["host"] != "example.com" {
		t.Fatalf("host header mismatch")
	}
	if parsed.Request.Headers["x-test"] != "a, b" {
		t.Fatalf("joined header mismatch: %q", parsed.Request.Headers["x-test"])
	}
	if string(parsed.Request.Body) != "hello" {
		t.Fatalf("body mismatch")
	}
	if string(parsed.Remaining) != "EXTRA" {
		t.Fatalf("remaining mismatch")
	}
}

func TestParseHttpRequestDecodesChunkedBody(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 1024})

	incomplete := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"5\r\nhe")
	parsed, err := backend.parseHttpRequest(incomplete)
	if err != nil {
		t.Fatalf("parse incomplete: %v", err)
	}
	if parsed != nil {
		t.Fatalf("expected incomplete")
	}

	complete := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"5\r\nhello\r\n" +
			"0\r\n\r\n")

	parsed, err = backend.parseHttpRequest(complete)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed == nil {
		t.Fatalf("expected parsed")
	}
	if parsed.Request.Headers["content-length"] != "5" {
		t.Fatalf("expected content-length 5")
	}
	if _, ok := parsed.Request.Headers["transfer-encoding"]; ok {
		t.Fatalf("expected transfer-encoding removed")
	}
	if string(parsed.Request.Body) != "hello" {
		t.Fatalf("body mismatch")
	}
	if len(parsed.Remaining) != 0 {
		t.Fatalf("expected no remaining")
	}
}

func TestParseHttpRequestConsumesChunkedTrailers(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 1024})

	complete := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"5\r\nhello\r\n" +
			"0\r\n" +
			"X-Trailer: yes\r\n" +
			"\r\n")

	parsed, err := backend.parseHttpRequest(complete)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed == nil {
		t.Fatalf("expected parsed")
	}
	if len(parsed.Remaining) != 0 {
		t.Fatalf("expected remaining empty")
	}
	if string(parsed.Request.Body) != "hello" {
		t.Fatalf("body mismatch")
	}
}

func TestParseHttpRequestRejectsUnsupportedTransferEncodings(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 1024})
	buf := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Transfer-Encoding: gzip, chunked\r\n" +
			"\r\n" +
			"5\r\nhello\r\n" +
			"0\r\n\r\n")

	_, err := backend.parseHttpRequest(buf)
	be, ok := err.(*HttpRequestBlockedError)
	if !ok || be.Status != 501 {
		t.Fatalf("expected 501 blocked error, got %T %v", err, err)
	}
}

func TestParseHttpRequestErrorsOnInvalidContentLength(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 1024})
	buf := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Content-Length: nope\r\n" +
			"\r\n" +
			"hello")

	_, err := backend.parseHttpRequest(buf)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseHttpRequestRejectsOversizedHeadersWithoutTerminator(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 1024})
	huge := "GET / HTTP/1.1\r\n" + "X: " + strings.Repeat("a", 70000)
	_, err := backend.parseHttpRequest([]byte(huge))
	be, ok := err.(*HttpRequestBlockedError)
	if !ok || be.Status != 431 {
		t.Fatalf("expected 431, got %T %v", err, err)
	}
}

func TestStripHopByHopHeadersRemovesNominatedByConnection(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{})
	stripped := backend.stripHopByHopHeaders(map[string]string{
		"host":         "example.com",
		"connection":   "x-foo, keep-alive",
		"keep-alive":   "timeout=5",
		"x-foo":        "bar",
		"x-ok":         "1",
	})
	if _, ok := stripped["x-foo"]; ok {
		t.Fatalf("expected x-foo stripped")
	}
	if _, ok := stripped["connection"]; ok {
		t.Fatalf("expected connection stripped")
	}
	if _, ok := stripped["keep-alive"]; ok {
		t.Fatalf("expected keep-alive stripped")
	}
	if stripped["x-ok"] != "1" {
		t.Fatalf("expected x-ok preserved")
	}
}

func TestHandleHttpDataWithWriterSends100ContinueWhenBodyPending(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 1024})

	writes := make([][]byte, 0, 2)
	sess := &TcpIngressSession{}

	err := backend.handleHttpDataWithWriter(
		"key",
		sess,
		[]byte(
			"POST / HTTP/1.1\r\n"+
				"Host: example.com\r\n"+
				"Expect: 100-continue\r\n"+
				"Content-Length: 5\r\n"+
				"\r\n"),
		httpWriter{scheme: "http", write: func(chunk []byte) { writes = append(writes, append([]byte(nil), chunk...)) }, finish: func() { t.Fatalf("unexpected finish") }},
	)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	out := string(bytes.Join(writes, nil))
	if !strings.Contains(out, "100 Continue") {
		t.Fatalf("expected 100 Continue, got %q", out)
	}
}

func TestHandleHttpDataWithWriterSends100ContinueForChunkedBodies(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 1024})

	writes := make([][]byte, 0, 2)
	sess := &TcpIngressSession{}

	err := backend.handleHttpDataWithWriter(
		"key",
		sess,
		[]byte(
			"POST / HTTP/1.1\r\n"+
				"Host: example.com\r\n"+
				"Expect: 100-continue\r\n"+
				"Transfer-Encoding: chunked\r\n"+
				"\r\n"+
				"1\r\n"+
				"h\r\n"),
		httpWriter{scheme: "http", write: func(chunk []byte) { writes = append(writes, append([]byte(nil), chunk...)) }, finish: func() { t.Fatalf("unexpected finish") }},
	)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	out := string(bytes.Join(writes, nil))
	if !strings.Contains(out, "100 Continue") {
		t.Fatalf("expected 100 Continue")
	}
}

func TestHandleHttpDataWithWriterEnforcesMaxPipelineBytesForChunkedRequests(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 1024})

	writes := make([][]byte, 0, 4)
	sess := &TcpIngressSession{}
	finished := false

	pipelineJunk := bytes.Repeat([]byte{0x61}, MAX_HTTP_PIPELINE_BYTES+1)

	err := backend.handleHttpDataWithWriter(
		"key",
		sess,
		append([]byte(
			"POST / HTTP/1.1\r\n"+
				"Host: example.com\r\n"+
				"Transfer-Encoding: chunked\r\n"+
				"\r\n"+
				"0\r\n\r\n"), pipelineJunk...),
		httpWriter{scheme: "http", write: func(chunk []byte) { writes = append(writes, append([]byte(nil), chunk...)) }, finish: func() { finished = true }},
	)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !finished {
		t.Fatalf("expected finish")
	}
	if sess.HTTP == nil || !sess.HTTP.Closed {
		t.Fatalf("expected closed")
	}
	out := string(bytes.Join(writes, nil))
	if !strings.Contains(out, "413") {
		t.Fatalf("expected 413")
	}
}

func TestHandleHttpDataWithWriterDoesNotSend100ContinueForUnsupportedTransferEncoding(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 1024})

	writes := make([][]byte, 0, 4)
	sess := &TcpIngressSession{}
	finished := false

	err := backend.handleHttpDataWithWriter(
		"key",
		sess,
		[]byte(
			"POST / HTTP/1.1\r\n"+
				"Host: example.com\r\n"+
				"Expect: 100-continue\r\n"+
				"Transfer-Encoding: gzip\r\n"+
				"\r\n"),
		httpWriter{scheme: "http", write: func(chunk []byte) { writes = append(writes, append([]byte(nil), chunk...)) }, finish: func() { finished = true }},
	)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !finished {
		t.Fatalf("expected finish")
	}
	out := string(bytes.Join(writes, nil))
	if strings.Contains(out, "100 Continue") {
		t.Fatalf("did not expect 100 Continue")
	}
	if !strings.Contains(out, "501") {
		t.Fatalf("expected 501")
	}
}

func TestParseHttpRequestReturns417ForUnsupportedExpect(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 1024})
	buf := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Expect: bananas\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n")

	_, err := backend.parseHttpRequest(buf)
	be, ok := err.(*HttpRequestBlockedError)
	if !ok || be.Status != 417 {
		t.Fatalf("expected 417, got %T %v", err, err)
	}
}

func TestParseHttpRequestEnforcesMaxHttpBodyBytes(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxHttpBodyBytes: 4})
	buf := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Content-Length: 5\r\n" +
			"\r\n" +
			"hello")
	_, err := backend.parseHttpRequest(buf)
	be, ok := err.(*HttpRequestBlockedError)
	if !ok || be.Status != 413 {
		t.Fatalf("expected 413, got %T %v", err, err)
	}
}

func TestFetchAndRespondFollowsRedirectsAndRewritesPostToGet(t *testing.T) {
	writes := make([][]byte, 0, 8)
	calls := make([]struct {
		url  string
		init HttpFetchInit
	}, 0, 2)

	fetchMock := func(u string, init HttpFetchInit) (*HttpFetchResponse, error) {
		calls = append(calls, struct {
			url  string
			init HttpFetchInit
		}{u, init})
		if len(calls) == 1 {
			return &HttpFetchResponse{Status: 302, Headers: map[string][]string{"location": {"/next"}}, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		}
		// redirect should become GET and drop body + related headers
		if init.Method != "GET" {
			t.Fatalf("expected GET, got %s", init.Method)
		}
		if init.Body != nil {
			t.Fatalf("expected body nil")
		}
		if _, ok := init.Headers["content-length"]; ok {
			t.Fatalf("did not expect content-length")
		}
		if _, ok := init.Headers["content-type"]; ok {
			t.Fatalf("did not expect content-type")
		}
		if _, ok := init.Headers["transfer-encoding"]; ok {
			t.Fatalf("did not expect transfer-encoding")
		}
		return &HttpFetchResponse{Status: 200, Headers: map[string][]string{"content-length": {"2"}}, Body: io.NopCloser(bytes.NewReader([]byte("ok")))}, nil
	}

	backend := makeBackend(t, QemuNetworkOptions{Fetch: fetchMock, HttpHooks: HttpHooks{IsAllowed: func(_ HttpAllowInfo) (bool, error) { return true, nil }}})
	backend.resolveHostname = func(_ string) (string, int, error) { return "203.0.113.1", 4, nil }

	req := &HttpRequestData{Method: "POST", Target: "/start", Version: "HTTP/1.1", Headers: map[string]string{"host": "example.com", "content-length": "5", "content-type": "text/plain"}, Body: []byte("hello")}

	err := backend.fetchAndRespond(req, "http", func(chunk []byte) {
		writes = append(writes, append([]byte(nil), chunk...))
	})
	if err != nil {
		t.Fatalf("fetchAndRespond: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("expected 2 calls")
	}
	respText := string(bytes.Join(writes, nil))
	if !strings.HasPrefix(respText, "HTTP/1.1 200 ") {
		t.Fatalf("unexpected response: %q", respText)
	}
	if !strings.Contains(strings.ToLower(respText), "connection: close") {
		t.Fatalf("expected connection close")
	}
	if !strings.HasSuffix(respText, "ok") {
		t.Fatalf("expected ok suffix")
	}
}

func TestFetchAndRespondRejectsOptionsAsterisk(t *testing.T) {
	writes := make([][]byte, 0, 2)
	fetchMock := func(_ string, _ HttpFetchInit) (*HttpFetchResponse, error) {
		t.Fatalf("fetch should not be called")
		return nil, nil
	}
	backend := makeBackend(t, QemuNetworkOptions{Fetch: fetchMock, HttpHooks: HttpHooks{IsAllowed: func(_ HttpAllowInfo) (bool, error) { return true, nil }}})

	req := &HttpRequestData{Method: "OPTIONS", Target: "*", Version: "HTTP/1.1", Headers: map[string]string{"host": "example.com"}, Body: []byte{}}
	_ = backend.fetchAndRespond(req, "http", func(chunk []byte) { writes = append(writes, append([]byte(nil), chunk...)) })

	resp := string(bytes.Join(writes, nil))
	if !strings.HasPrefix(resp, "HTTP/1.1 501 ") {
		t.Fatalf("expected 501")
	}
}

func TestFetchAndRespondRejectsWebSocketUpgrade(t *testing.T) {
	writes := make([][]byte, 0, 2)
	fetchMock := func(_ string, _ HttpFetchInit) (*HttpFetchResponse, error) {
		t.Fatalf("fetch should not be called")
		return nil, nil
	}
	backend := makeBackend(t, QemuNetworkOptions{Fetch: fetchMock, HttpHooks: HttpHooks{IsAllowed: func(_ HttpAllowInfo) (bool, error) { return true, nil }}})

	req := &HttpRequestData{Method: "GET", Target: "/", Version: "HTTP/1.1", Headers: map[string]string{"host": "example.com", "connection": "Upgrade", "upgrade": "websocket", "sec-websocket-key": "x", "sec-websocket-version": "13"}, Body: []byte{}}
	_ = backend.fetchAndRespond(req, "http", func(chunk []byte) { writes = append(writes, append([]byte(nil), chunk...)) })

	resp := string(bytes.Join(writes, nil))
	if !strings.HasPrefix(resp, "HTTP/1.1 501 ") {
		t.Fatalf("expected 501")
	}
}

func TestFetchAndRespondSuppressesBodyForHEAD(t *testing.T) {
	writes := make([][]byte, 0, 8)
	fetchMock := func(_ string, _ HttpFetchInit) (*HttpFetchResponse, error) {
		return &HttpFetchResponse{Status: 200, Headers: map[string][]string{"content-length": {"2"}}, Body: io.NopCloser(bytes.NewReader([]byte("ok")))}, nil
	}
	backend := makeBackend(t, QemuNetworkOptions{Fetch: fetchMock, HttpHooks: HttpHooks{IsAllowed: func(_ HttpAllowInfo) (bool, error) { return true, nil }}})
	backend.resolveHostname = func(_ string) (string, int, error) { return "203.0.113.3", 4, nil }

	req := &HttpRequestData{Method: "HEAD", Target: "/", Version: "HTTP/1.1", Headers: map[string]string{"host": "example.com"}, Body: []byte{}}
	_ = backend.fetchAndRespond(req, "http", func(chunk []byte) { writes = append(writes, append([]byte(nil), chunk...)) })

	raw := string(bytes.Join(writes, nil))
	if !strings.HasPrefix(raw, "HTTP/1.1 200 ") {
		t.Fatalf("unexpected: %q", raw)
	}
	if !strings.Contains(strings.ToLower(raw), "content-length: 2") {
		t.Fatalf("expected content-length 2")
	}
	he := strings.Index(raw, "\r\n\r\n")
	if he == -1 {
		t.Fatalf("missing header end")
	}
	if raw[he+4:] != "" {
		t.Fatalf("expected empty body")
	}
}

func TestFetchAndRespondSuppressesBodyFor204And304(t *testing.T) {
	for _, status := range []int{204, 304} {
		writes := make([][]byte, 0, 8)
		fetchMock := func(_ string, _ HttpFetchInit) (*HttpFetchResponse, error) {
			return &HttpFetchResponse{Status: status, Headers: map[string][]string{}, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		}
		backend := makeBackend(t, QemuNetworkOptions{Fetch: fetchMock, HttpHooks: HttpHooks{IsAllowed: func(_ HttpAllowInfo) (bool, error) { return true, nil }}})
		backend.resolveHostname = func(_ string) (string, int, error) { return "203.0.113.4", 4, nil }
		req := &HttpRequestData{Method: "GET", Target: "/", Version: "HTTP/1.1", Headers: map[string]string{"host": "example.com"}, Body: []byte{}}
		_ = backend.fetchAndRespond(req, "http", func(chunk []byte) { writes = append(writes, append([]byte(nil), chunk...)) })
		raw := string(bytes.Join(writes, nil))
		if !strings.HasPrefix(raw, "HTTP/1.1 "+strconv.Itoa(status)+" ") {
			t.Fatalf("unexpected status")
		}
		if !strings.Contains(strings.ToLower(raw), "content-length: 0") {
			t.Fatalf("expected content-length 0")
		}
		he := strings.Index(raw, "\r\n\r\n")
		if he == -1 {
			t.Fatalf("missing header end")
		}
		if raw[he+4:] != "" {
			t.Fatalf("expected empty body")
		}
	}
}

type fixedChunkReader struct {
	chunks [][]byte
	idx    int
}

func (r *fixedChunkReader) Read(p []byte) (int, error) {
	if r.idx >= len(r.chunks) {
		return 0, io.EOF
	}
	c := r.chunks[r.idx]
	r.idx++
	copy(p, c)
	return len(c), nil
}

type cancelRC struct {
	r io.Reader
	cancelled *bool
}

func (c *cancelRC) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *cancelRC) Close() error {
	if c.cancelled != nil {
		*c.cancelled = true
	}
	return nil
}

func TestFetchAndRespondStreamsChunkedBodyWhenEncodedUnknownLength(t *testing.T) {
	writes := make([][]byte, 0, 16)

	fetchMock := func(_ string, _ HttpFetchInit) (*HttpFetchResponse, error) {
		body := io.NopCloser(&fixedChunkReader{chunks: [][]byte{[]byte("one"), []byte("two")}})
		return &HttpFetchResponse{Status: 200, StatusText: "OK", Headers: map[string][]string{"content-encoding": {"gzip"}}, Body: body}, nil
	}

	backend := makeBackend(t, QemuNetworkOptions{Fetch: fetchMock, HttpHooks: HttpHooks{IsAllowed: func(_ HttpAllowInfo) (bool, error) { return true, nil }}})
	backend.resolveHostname = func(_ string) (string, int, error) { return "203.0.113.2", 4, nil }

	req := &HttpRequestData{Method: "GET", Target: "/", Version: "HTTP/1.1", Headers: map[string]string{"host": "example.com"}, Body: []byte{}}
	_ = backend.fetchAndRespond(req, "http", func(chunk []byte) { writes = append(writes, append([]byte(nil), chunk...)) })

	raw := string(bytes.Join(writes, nil))
	he := strings.Index(raw, "\r\n\r\n")
	if he == -1 {
		t.Fatalf("missing header end")
	}
	head := strings.ToLower(raw[:he])
	bodyText := raw[he+4:]
	if !strings.Contains(head, "transfer-encoding: chunked") {
		t.Fatalf("expected chunked")
	}
	if strings.Contains(head, "content-encoding") {
		t.Fatalf("did not expect content-encoding")
	}
	if !strings.Contains(bodyText, "3\r\none\r\n") || !strings.Contains(bodyText, "3\r\ntwo\r\n") || !strings.Contains(bodyText, "0\r\n\r\n") {
		t.Fatalf("unexpected body: %q", bodyText)
	}
}

func TestFetchAndRespondPreservesMultipleSetCookieHeaders(t *testing.T) {
	writes := make([][]byte, 0, 16)
	sawHook := false

	fetchMock := func(_ string, _ HttpFetchInit) (*HttpFetchResponse, error) {
		return &HttpFetchResponse{Status: 200, StatusText: "OK", Headers: map[string][]string{"content-length": {"2"}, "set-cookie": {"a=1", "b=2"}}, Body: io.NopCloser(bytes.NewReader([]byte("ok")))}, nil
	}

	backend := makeBackend(t, QemuNetworkOptions{Fetch: fetchMock, HttpHooks: HttpHooks{IsAllowed: func(_ HttpAllowInfo) (bool, error) { return true, nil }, OnResponse: func(resp HttpHookResponse, _ HttpHookRequest) (*HttpHookResponse, error) {
		sawHook = true
		cookies := resp.Headers["set-cookie"]
		if len(cookies) != 2 || cookies[0] != "a=1" || cookies[1] != "b=2" {
			t.Fatalf("unexpected cookies: %v", cookies)
		}
		return &resp, nil
	}}})
	backend.resolveHostname = func(_ string) (string, int, error) { return "203.0.113.21", 4, nil }

	req := &HttpRequestData{Method: "GET", Target: "/", Version: "HTTP/1.1", Headers: map[string]string{"host": "example.com"}, Body: []byte{}}
	_ = backend.fetchAndRespond(req, "http", func(chunk []byte) { writes = append(writes, append([]byte(nil), chunk...)) })

	if !sawHook {
		t.Fatalf("expected hook")
	}

	raw := strings.ToLower(string(bytes.Join(writes, nil)))
	he := strings.Index(raw, "\r\n\r\n")
	if he == -1 {
		t.Fatalf("missing header end")
	}
	head := raw[:he]
	if !strings.Contains(head, "\r\nset-cookie: a=1\r\n") || !strings.Contains(head, "\r\nset-cookie: b=2\r\n") {
		t.Fatalf("expected separate set-cookie lines")
	}
}

func TestFetchAndRespondHttp10NoChunked(t *testing.T) {
	writes := make([][]byte, 0, 16)
	fetchMock := func(_ string, _ HttpFetchInit) (*HttpFetchResponse, error) {
		body := io.NopCloser(&fixedChunkReader{chunks: [][]byte{[]byte("one"), []byte("two")}})
		return &HttpFetchResponse{Status: 200, StatusText: "OK", Headers: map[string][]string{"content-encoding": {"gzip"}}, Body: body}, nil
	}
	backend := makeBackend(t, QemuNetworkOptions{Fetch: fetchMock, HttpHooks: HttpHooks{IsAllowed: func(_ HttpAllowInfo) (bool, error) { return true, nil }}})
	backend.resolveHostname = func(_ string) (string, int, error) { return "203.0.113.20", 4, nil }

	req := &HttpRequestData{Method: "GET", Target: "/", Version: "HTTP/1.0", Headers: map[string]string{"host": "example.com"}, Body: []byte{}}
	_ = backend.fetchAndRespond(req, "http", func(chunk []byte) { writes = append(writes, append([]byte(nil), chunk...)) })

	raw := string(bytes.Join(writes, nil))
	he := strings.Index(raw, "\r\n\r\n")
	if he == -1 {
		t.Fatalf("missing header end")
	}
	head := strings.ToLower(raw[:he])
	bodyText := raw[he+4:]
	if !strings.HasPrefix(raw, "HTTP/1.0 200 ") {
		t.Fatalf("expected HTTP/1.0")
	}
	if strings.Contains(head, "transfer-encoding") {
		t.Fatalf("did not expect transfer-encoding")
	}
	if strings.Contains(head, "content-encoding") {
		t.Fatalf("did not expect content-encoding")
	}
	if bodyText != "onetwo" {
		t.Fatalf("body mismatch: %q", bodyText)
	}
}

func TestFetchAndRespondEnforcesMaxHttpResponseBodyBytesWhenBufferingKnownLength(t *testing.T) {
	cancelled := false
	hookCalls := 0

	fetchMock := func(_ string, _ HttpFetchInit) (*HttpFetchResponse, error) {
		body := &cancelRC{r: &fixedChunkReader{chunks: [][]byte{[]byte("hello")}}, cancelled: &cancelled}
		return &HttpFetchResponse{Status: 200, Headers: map[string][]string{"content-length": {"5"}}, Body: body}, nil
	}

	max := 4
	backend := makeBackend(t, QemuNetworkOptions{Fetch: fetchMock, MaxHttpResponseBodyBytes: max, HttpHooks: HttpHooks{IsAllowed: func(_ HttpAllowInfo) (bool, error) { return true, nil }, OnResponse: func(resp HttpHookResponse, _ HttpHookRequest) (*HttpHookResponse, error) {
		hookCalls++
		return &resp, nil
	}}})
	backend.resolveHostname = func(_ string) (string, int, error) { return "203.0.113.10", 4, nil }

	req := &HttpRequestData{Method: "GET", Target: "/", Version: "HTTP/1.1", Headers: map[string]string{"host": "example.com"}, Body: []byte{}}
	err := backend.fetchAndRespond(req, "http", func([]byte) {})
	be, ok := err.(*HttpRequestBlockedError)
	if !ok || be.Status != 502 {
		t.Fatalf("expected 502 error, got %T %v", err, err)
	}
	if hookCalls != 0 {
		t.Fatalf("expected hookCalls 0")
	}
	if !cancelled {
		t.Fatalf("expected cancelled")
	}
}

func TestFetchAndRespondEnforcesMaxHttpResponseBodyBytesWhenBufferingUnknownLength(t *testing.T) {
	cancelled := false
	hookCalls := 0

	fetchMock := func(_ string, _ HttpFetchInit) (*HttpFetchResponse, error) {
		body := &cancelRC{r: &fixedChunkReader{chunks: [][]byte{[]byte("he"), []byte("llo"), []byte("more")}}, cancelled: &cancelled}
		return &HttpFetchResponse{Status: 200, Headers: map[string][]string{"content-encoding": {"gzip"}}, Body: body}, nil
	}

	max := 4
	backend := makeBackend(t, QemuNetworkOptions{Fetch: fetchMock, MaxHttpResponseBodyBytes: max, HttpHooks: HttpHooks{IsAllowed: func(_ HttpAllowInfo) (bool, error) { return true, nil }, OnResponse: func(resp HttpHookResponse, _ HttpHookRequest) (*HttpHookResponse, error) {
		hookCalls++
		return &resp, nil
	}}})
	backend.resolveHostname = func(_ string) (string, int, error) { return "203.0.113.11", 4, nil }

	req := &HttpRequestData{Method: "GET", Target: "/", Version: "HTTP/1.1", Headers: map[string]string{"host": "example.com"}, Body: []byte{}}
	err := backend.fetchAndRespond(req, "http", func([]byte) {})
	be, ok := err.(*HttpRequestBlockedError)
	if !ok || be.Status != 502 {
		t.Fatalf("expected 502 error, got %T %v", err, err)
	}
	if hookCalls != 0 {
		t.Fatalf("expected hookCalls 0")
	}
	if !cancelled {
		t.Fatalf("expected cancelled")
	}
}

func TestCreateLookupGuardFiltersDnsResultsViaIsAllowed(t *testing.T) {
	lookupMock := func(_ string, options any, cb func(err error, address any, family int)) {
		if m, ok := options.(map[string]any); ok {
			if all, _ := m["all"].(bool); all {
				cb(nil, []any{map[string]any{"address": "127.0.0.1", "family": 4}, map[string]any{"address": "93.184.216.34", "family": 4}}, 0)
				return
			}
		}
		cb(nil, "127.0.0.1", 4)
	}

	isAllowed := func(info HttpAllowInfo) (bool, error) { return info.IP != "127.0.0.1", nil }
	guarded := CreateLookupGuard(LookupInfo{Hostname: "example.com", Port: 443, Protocol: "https"}, isAllowed, lookupMock)

	// all:false should fail
	ch := make(chan error, 1)
	guarded("example.com", map[string]any{"family": 4}, func(err error, _ any, _ int) {
		ch <- err
	})
	if err := <-ch; err == nil {
		t.Fatalf("expected error")
	}

	// all:true should filter
	ch2 := make(chan any, 1)
	guarded("example.com", map[string]any{"all": true}, func(err error, addr any, _ int) {
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		ch2 <- addr
	})
	addrAny := <-ch2
	arr := addrAny.([]any)
	if len(arr) != 1 {
		t.Fatalf("expected 1 entry")
	}
	m := arr[0].(map[string]any)
	if m["address"].(string) != "93.184.216.34" {
		t.Fatalf("unexpected address")
	}
}

func TestTlsMitmGeneratesLeafCertificatesPerHost(t *testing.T) {
	dir, err := os.MkdirTemp("", "gondolin-mitm-test-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	defer os.RemoveAll(dir)

	backend := makeBackend(t, QemuNetworkOptions{MitmCertDir: dir})

	ctx1, err := backend.getTlsContextAsync("example.com")
	if err != nil || ctx1 == nil {
		t.Fatalf("expected tls context")
	}

	hostsDir := filepath.Join(dir, "hosts")
	entries, err := os.ReadDir(hostsDir)
	if err != nil {
		t.Fatalf("expected hosts dir")
	}
	files1 := make([]string, 0)
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".key") {
			files1 = append(files1, name)
		}
	}
	if len(files1) == 0 {
		t.Fatalf("expected leaf files")
	}

	var crtPath string
	for _, f := range files1 {
		if strings.HasSuffix(f, ".crt") {
			crtPath = filepath.Join(hostsDir, f)
			break
		}
	}
	pemBytes, _ := os.ReadFile(crtPath)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("failed to decode leaf cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	found := false
	for _, dns := range cert.DNSNames {
		if dns == "example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected SAN example.com")
	}

	ctx2, err := backend.getTlsContextAsync("example.com")
	if err != nil || ctx2 == nil {
		t.Fatalf("expected tls context")
	}

	entries2, _ := os.ReadDir(hostsDir)
	files2 := make([]string, 0)
	for _, e := range entries2 {
		name := e.Name()
		if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".key") {
			files2 = append(files2, name)
		}
	}
	if len(files2) != len(files1) {
		t.Fatalf("expected no new files")
	}
}

func TestTlsContextCacheLruAndTtl(t *testing.T) {
	ms := 60_000
	backend := makeBackend(t, QemuNetworkOptions{TlsContextCacheMaxEntries: 3, TlsContextCacheTtlMs: &ms})

	created := 0
	backend.createTlsContext = func(_ string) (*tls.Config, error) {
		created++
		return &tls.Config{}, nil
	}

	_, _ = backend.getTlsContextAsync("a.example")
	_, _ = backend.getTlsContextAsync("b.example")
	_, _ = backend.getTlsContextAsync("c.example")
	if len(backend.tlsCache) != 3 {
		t.Fatalf("expected cache size 3")
	}

	// touch b
	_, _ = backend.getTlsContextAsync("b.example")
	_, _ = backend.getTlsContextAsync("d.example")

	if len(backend.tlsCache) != 3 {
		t.Fatalf("expected cache size 3")
	}
	if _, ok := backend.tlsCache["a.example"]; ok {
		t.Fatalf("expected a evicted")
	}
	if created != 4 {
		t.Fatalf("expected 4 created, got %d", created)
	}

	// ttl test
	ms2 := 50
	backend2 := makeBackend(t, QemuNetworkOptions{TlsContextCacheMaxEntries: 100, TlsContextCacheTtlMs: &ms2})
	created2 := 0
	backend2.createTlsContext = func(_ string) (*tls.Config, error) {
		created2++
		return &tls.Config{}, nil
	}
	_, _ = backend2.getTlsContextAsync("ttl.example")
	if created2 != 1 {
		t.Fatalf("expected created=1")
	}
	time.Sleep(80 * time.Millisecond)
	_, _ = backend2.getTlsContextAsync("ttl.example")
	if created2 != 2 {
		t.Fatalf("expected ttl to expire")
	}

	// ttl<=0 disables caching
	zero := 0
	backend3 := makeBackend(t, QemuNetworkOptions{TlsContextCacheMaxEntries: 100, TlsContextCacheTtlMs: &zero})
	created3 := 0
	backend3.createTlsContext = func(_ string) (*tls.Config, error) {
		created3++
		return &tls.Config{}, nil
	}
	_, _ = backend3.getTlsContextAsync("a.example")
	_, _ = backend3.getTlsContextAsync("a.example")
	if created3 != 2 {
		t.Fatalf("expected cache disabled")
	}
	_, _ = backend3.getTlsContextAsync("b.example")
	if created3 != 3 {
		t.Fatalf("expected created=3")
	}
	if len(backend3.tlsCache) != 1 {
		t.Fatalf("expected cache size 1")
	}
}

func buildQueryA(name string, id uint16) []byte {
	labels := strings.Split(name, ".")
	qnameParts := make([]byte, 0, 64)
	for _, label := range labels {
		if label == "" {
			continue
		}
		qnameParts = append(qnameParts, byte(len(label)))
		qnameParts = append(qnameParts, []byte(label)...)
	}
	qnameParts = append(qnameParts, 0)

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], 0x0100)
	binary.BigEndian.PutUint16(header[4:6], 1)

	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], 1)
	binary.BigEndian.PutUint16(tail[2:4], 1)

	out := append(header, qnameParts...)
	out = append(out, tail...)
	return out
}

type FakeUdpSocket struct {
	LastSend struct {
		Buf     []byte
		Port    int
		Address string
		Ok      bool
	}
	onMessage func(data []byte, address string, port int)
	onError func(err error)
}

func (s *FakeUdpSocket) Send(buf []byte, port int, address string) {
	s.LastSend.Buf = append([]byte(nil), buf...)
	s.LastSend.Port = port
	s.LastSend.Address = address
	s.LastSend.Ok = true
}

func (s *FakeUdpSocket) Close() {}

func (s *FakeUdpSocket) SetOnMessage(fn func(data []byte, address string, port int)) { s.onMessage = fn }
func (s *FakeUdpSocket) SetOnError(fn func(err error)) { s.onError = fn }

func (s *FakeUdpSocket) EmitMessage(data []byte, address string, port int) {
	if s.onMessage != nil {
		s.onMessage(data, address, port)
	}
}

func TestCapsGuestToUpstreamPendingWritesAndAbortsOnOverflow(t *testing.T) {
	backend := makeBackend(t, QemuNetworkOptions{MaxTCPPendingWriteBytes: 16})

	stackCalls := 0
	backend.stackTcp = stackTcpErrorFunc(func(_ string) { stackCalls++ })

	key := "TCP:1.2.3.4:111:5.6.7.8:222"
	backend.tcpSessions[key] = &tcpSession{PendingWrites: nil, PendingWriteBytes: 0}

	backend.HandleTcpSend(key, bytes.Repeat([]byte{0}, 32))
	if stackCalls != 1 {
		t.Fatalf("expected stack error")
	}
	if _, ok := backend.tcpSessions[key]; ok {
		t.Fatalf("expected session removed")
	}
}

type stackTcpErrorFunc func(key string)

func (f stackTcpErrorFunc) HandleTcpError(key string) { f(key) }

func TestDnsTrustedModeRewritesUpstreamResolverAndPreservesGuestDstIP(t *testing.T) {
	fake := &FakeUdpSocket{}
	backend := makeBackend(t, QemuNetworkOptions{Dns: DnsOptions{Mode: DnsModeTrusted, TrustedServers: []string{"1.1.1.1"}}, UdpSocketFactory: func() UdpSocket { return fake }})

	responses := make([]map[string]any, 0, 1)
	backend.stackUdp = stackUdpFunc(func(msg any) {
		responses = append(responses, msg.(map[string]any))
	})

	payload := buildQueryA("example.com", 0x1111)
	backend.HandleUdpSend(UdpSendMessage{Key: "udp1", SrcIP: "192.168.127.3", SrcPort: 40000, DstIP: "9.9.9.9", DstPort: 53, Payload: payload})

	if !fake.LastSend.Ok {
		t.Fatalf("expected send")
	}
	if fake.LastSend.Address != "1.1.1.1" {
		t.Fatalf("expected upstream 1.1.1.1")
	}
	if fake.LastSend.Port != 53 {
		t.Fatalf("expected port 53")
	}

	fake.EmitMessage([]byte{0, 1, 2, 3}, "1.1.1.1", 53)
	if len(responses) != 1 {
		t.Fatalf("expected one response")
	}
	if responses[0]["dstIP"].(string) != "9.9.9.9" {
		t.Fatalf("expected dstIP preserved")
	}
	if responses[0]["dstPort"].(uint16) != 53 {
		t.Fatalf("expected dstPort preserved")
	}
}

type stackUdpFunc func(msg any)

func (f stackUdpFunc) HandleUdpResponse(msg any) { f(msg) }

func TestDnsSyntheticModeRepliesWithoutOpeningUdpSocket(t *testing.T) {
	created := 0
	backend := makeBackend(t, QemuNetworkOptions{Dns: DnsOptions{Mode: DnsModeSynthetic}, UdpSocketFactory: func() UdpSocket { created++; return &FakeUdpSocket{} }})

	responses := make([]map[string]any, 0, 1)
	backend.stackUdp = stackUdpFunc(func(msg any) {
		responses = append(responses, msg.(map[string]any))
	})

	payload := buildQueryA("example.com", 0x2222)
	backend.HandleUdpSend(UdpSendMessage{Key: "udp2", SrcIP: "192.168.127.3", SrcPort: 40001, DstIP: "192.168.127.1", DstPort: 53, Payload: payload})

	if created != 0 {
		t.Fatalf("expected no socket created")
	}
	if len(responses) != 1 {
		t.Fatalf("expected one response")
	}
	resp := responses[0]["data"].([]byte)
	if binary.BigEndian.Uint16(resp[0:2]) != 0x2222 {
		t.Fatalf("id mismatch")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatalf("expected ANCOUNT=1")
	}
	if !bytes.Equal(resp[len(resp)-4:], []byte{192, 0, 2, 1}) {
		t.Fatalf("unexpected rdata")
	}
}
