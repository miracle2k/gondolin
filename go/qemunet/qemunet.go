package qemunet

import (
	"bufio"
	"bytes"
	"container/list"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	gondolindns "github.com/earendil-works/gondolin-go/dns"
	"github.com/earendil-works/gondolin-go/mitm"
)

const (
	maxHTTPRedirects      = 10
	maxHTTPHeaderBytes    = 64 * 1024
	MAX_HTTP_PIPELINE_BYTES = 64 * 1024
	maxHTTPChunkedOverheadBytes = 256 * 1024
)

const (
	DefaultMaxHTTPBodyBytes         = 64 * 1024 * 1024
	DefaultMaxHTTPResponseBodyBytes = DefaultMaxHTTPBodyBytes
	DefaultMaxTCPPendingWriteBytes  = 4 * 1024 * 1024

	defaultTlsContextCacheMaxEntries = 256
	defaultTlsContextCacheTtl        = 10 * time.Minute
)

type DnsMode string

const (
	DnsModeOpen      DnsMode = "open"
	DnsModeTrusted   DnsMode = "trusted"
	DnsModeSynthetic DnsMode = "synthetic"
)

const (
	defaultDnsMode              = DnsModeSynthetic
	defaultSyntheticDnsIPv4     = "192.0.2.1"
	defaultSyntheticDnsIPv6     = "2001:db8::1"
	defaultSyntheticDnsTtlSeconds = 60
)

type HttpRequestBlockedError struct {
	Message    string
	Status     int
	StatusText string
}

func (e *HttpRequestBlockedError) Error() string {
	if e.Message == "" {
		return "request blocked"
	}
	return e.Message
}

func NewHttpRequestBlockedError(message string, status int, statusText string) *HttpRequestBlockedError {
	if status == 0 {
		status = 403
	}
	if statusText == "" {
		statusText = "Forbidden"
	}
	return &HttpRequestBlockedError{Message: message, Status: status, StatusText: statusText}
}

type HttpAllowInfo struct {
	Hostname  string
	IP        string
	Family    int
	Port      int
	Protocol  string // "http" | "https"
}

type HttpHookRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte // nil means no body
}

type HttpHookResponse struct {
	Status     int
	StatusText string
	Headers    map[string][]string
	Body       []byte
}

type HttpHooks struct {
	IsAllowed func(info HttpAllowInfo) (bool, error)
	OnRequest func(req HttpHookRequest) (*HttpHookRequest, error)
	OnResponse func(resp HttpHookResponse, req HttpHookRequest) (*HttpHookResponse, error)
}

type DnsOptions struct {
	Mode              DnsMode
	TrustedServers    []string
	SyntheticIPv4     string
	SyntheticIPv6     string
	SyntheticTtlSeconds uint32
}

type HttpFetchInit struct {
	Method  string
	Headers map[string]string
	Body    []byte // nil means no body
}

type HttpFetchResponse struct {
	Status     int
	StatusText string
	Headers    map[string][]string
	Body       io.ReadCloser
}

type HttpFetch func(url string, init HttpFetchInit) (*HttpFetchResponse, error)

// UdpSocket is a minimal abstraction so tests can stub DNS I/O.
//
// Implementations must call the registered handlers when datagrams arrive.
type UdpSocket interface {
	Send(buf []byte, port int, address string)
	Close()
	SetOnMessage(fn func(data []byte, address string, port int))
	SetOnError(fn func(err error))
}

type QemuNetworkOptions struct {
	SocketPath string
	Debug      bool
	Dns        DnsOptions
	Fetch      HttpFetch
	HttpHooks  HttpHooks
	MitmCertDir string
	MaxHttpBodyBytes int
	MaxHttpResponseBodyBytes int
	MaxTCPPendingWriteBytes int
	TlsContextCacheMaxEntries int
	TlsContextCacheTtlMs *int
	UdpSocketFactory func() UdpSocket
}

type tcpSession struct {
	PendingWrites     [][]byte
	PendingWriteBytes int
}

type udpSession struct {
	Socket UdpSocket
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	UpstreamIP   string
	UpstreamPort int
}

type stackUdpResponder interface {
	HandleUdpResponse(msg any)
}

type stackTcpError interface {
	HandleTcpError(key string)
}

type QemuNetworkBackend struct {
	options QemuNetworkOptions

	dnsMode DnsMode
	trustedDnsServers []string
	trustedDnsIndex int

	syntheticDnsOpts gondolindns.SyntheticDnsResponseOptions

	udpSessions map[string]*udpSession
	tcpSessions map[string]*tcpSession

	maxHttpBodyBytes int
	maxHttpResponseBodyBytes int
	maxTcpPendingWriteBytes int

	// Hooks and fetch
	fetch HttpFetch
	httpHooks HttpHooks

	// resolveHostname is overridable for tests.
	resolveHostname func(hostname string) (ip string, family int, err error)

	// tls MITM
	mitmCertDir string
	mitmMu sync.Mutex
	mitmCa *mitm.MitmCa

	tlsCacheMu sync.Mutex
	tlsCacheMaxEntries int
	tlsCacheTtl time.Duration
	// map key -> list element for LRU
	tlsCache map[string]*list.Element
	tlsLru *list.List

	// injectable for tests
	createTlsContext func(servername string) (*tls.Config, error)

	// stack hooks for tests
	stackUdp stackUdpResponder
	stackTcp stackTcpError
}

type tlsCacheEntry struct {
	Servername string
	Config *tls.Config
	LastAccess time.Time
}

func NewQemuNetworkBackend(options QemuNetworkOptions) (*QemuNetworkBackend, error) {
	mode := options.Dns.Mode
	if mode == "" {
		mode = defaultDnsMode
	}

	trusted := normalizeIpv4Servers(options.Dns.TrustedServers)
	if mode == DnsModeTrusted && len(trusted) == 0 {
		return nil, fmt.Errorf("dns mode 'trusted' requires at least one IPv4 resolver (none configured/found)")
	}

	synthIPv4 := options.Dns.SyntheticIPv4
	if synthIPv4 == "" {
		synthIPv4 = defaultSyntheticDnsIPv4
	}
	synthIPv6 := options.Dns.SyntheticIPv6
	if synthIPv6 == "" {
		synthIPv6 = defaultSyntheticDnsIPv6
	}
	ttl := options.Dns.SyntheticTtlSeconds
	if ttl == 0 {
		ttl = defaultSyntheticDnsTtlSeconds
	}

	maxBody := options.MaxHttpBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxHTTPBodyBytes
	}
	maxRespBody := options.MaxHttpResponseBodyBytes
	if maxRespBody <= 0 {
		maxRespBody = DefaultMaxHTTPResponseBodyBytes
	}
	maxPending := options.MaxTCPPendingWriteBytes
	if maxPending <= 0 {
		maxPending = DefaultMaxTCPPendingWriteBytes
	}

	cacheMax := options.TlsContextCacheMaxEntries
	if cacheMax <= 0 {
		cacheMax = defaultTlsContextCacheMaxEntries
	}
	cacheTtl := defaultTlsContextCacheTtl
	if options.TlsContextCacheTtlMs != nil {
		cacheTtl = time.Duration(*options.TlsContextCacheTtlMs) * time.Millisecond
	}

	backend := &QemuNetworkBackend{
		options: options,
		dnsMode: mode,
		trustedDnsServers: trusted,
		trustedDnsIndex: 0,
		syntheticDnsOpts: gondolindns.SyntheticDnsResponseOptions{
			IPv4: synthIPv4,
			IPv6: synthIPv6,
			TtlSeconds: ttl,
		},
		udpSessions: map[string]*udpSession{},
		tcpSessions: map[string]*tcpSession{},
		maxHttpBodyBytes: maxBody,
		maxHttpResponseBodyBytes: maxRespBody,
		maxTcpPendingWriteBytes: maxPending,
		fetch: options.Fetch,
		httpHooks: options.HttpHooks,
		mitmCertDir: mitm.ResolveMitmCertDir(options.MitmCertDir),
		tlsCacheMaxEntries: cacheMax,
		tlsCacheTtl: cacheTtl,
		tlsCache: map[string]*list.Element{},
		tlsLru: list.New(),
	}

	backend.resolveHostname = backend.defaultResolveHostname
	backend.createTlsContext = backend.defaultCreateTlsContext

	return backend, nil
}

func normalizeIpv4Servers(servers []string) []string {
	unique := make([]string, 0, len(servers))
	seen := map[string]struct{}{}
	for _, s := range servers {
		s = strings.Split(s, "%")[0]
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		unique = append(unique, s)
	}
	return unique
}

// -------------------- HTTP parsing --------------------

type HttpRequestData struct {
	Method  string
	Target  string
	Version string
	Headers map[string]string
	Body    []byte
}

type parsedRequest struct {
	Request   *HttpRequestData
	Remaining []byte
}

func (b *QemuNetworkBackend) parseHttpRequest(buf []byte) (*parsedRequest, error) {
	// Fast-path: find header terminator.
	headerEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		if len(buf) > maxHTTPHeaderBytes {
			return nil, NewHttpRequestBlockedError("header too large", 431, "Request Header Fields Too Large")
		}
		return nil, nil
	}
	if headerEnd > maxHTTPHeaderBytes {
		return nil, NewHttpRequestBlockedError("header too large", 431, "Request Header Fields Too Large")
	}

	headersBlock := buf[:headerEnd]
	lines := strings.Split(string(headersBlock), "\r\n")
	if len(lines) == 0 {
		return nil, NewHttpRequestBlockedError("bad request", 400, "Bad Request")
	}
	line := lines[0]
	parts := strings.Split(line, " ")
	if len(parts) < 3 {
		return nil, NewHttpRequestBlockedError("bad request", 400, "Bad Request")
	}
	method := parts[0]
	target := parts[1]
	version := parts[2]

	headers := map[string]string{}
	for _, l := range lines[1:] {
		if l == "" {
			break
		}
		idx := strings.Index(l, ":")
		if idx == -1 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(l[:idx]))
		value := strings.TrimSpace(l[idx+1:])
		if name == "" {
			continue
		}
		if prev, ok := headers[name]; ok {
			headers[name] = prev + ", " + value
		} else {
			headers[name] = value
		}
	}

	// Validate Expect header.
	if exp, ok := headers["expect"]; ok {
		tokens := splitHeaderTokens(exp)
		for _, t := range tokens {
			if strings.ToLower(t) != "100-continue" {
				return nil, NewHttpRequestBlockedError("expectation failed", 417, "Expectation Failed")
			}
		}
	}

	// Parse body
	bodyStart := headerEnd + 4
	rest := buf[bodyStart:]

	// Transfer-Encoding handling
	if te, ok := headers["transfer-encoding"]; ok {
		enc := parseTransferEncoding(te)
		if enc != "chunked" {
			return nil, NewHttpRequestBlockedError("transfer-encoding not implemented", 501, "Not Implemented")
		}

		decoded, consumed, complete, err := decodeChunked(rest, b.maxHttpBodyBytes)
		if err != nil {
			return nil, err
		}
		if !complete {
			return nil, nil
		}
		// Cap chunked framing overhead
		if consumed-len(decoded) > maxHTTPChunkedOverheadBytes {
			return nil, NewHttpRequestBlockedError("chunked overhead too large", 413, "Payload Too Large")
		}

		delete(headers, "transfer-encoding")
		headers["content-length"] = strconv.Itoa(len(decoded))

		remaining := rest[consumed:]
		return &parsedRequest{Request: &HttpRequestData{Method: method, Target: target, Version: version, Headers: headers, Body: decoded}, Remaining: remaining}, nil
	}

	cl := headers["content-length"]
	if cl == "" {
		// no body
		remaining := rest
		return &parsedRequest{Request: &HttpRequestData{Method: method, Target: target, Version: version, Headers: headers, Body: []byte{}}, Remaining: remaining}, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(cl))
	if err != nil || n < 0 {
		return nil, NewHttpRequestBlockedError("invalid content-length", 400, "Bad Request")
	}
	if n > b.maxHttpBodyBytes {
		return nil, NewHttpRequestBlockedError("payload too large", 413, "Payload Too Large")
	}
	if len(rest) < n {
		return nil, nil
	}
	body := rest[:n]
	remaining := rest[n:]
	return &parsedRequest{Request: &HttpRequestData{Method: method, Target: target, Version: version, Headers: headers, Body: append([]byte(nil), body...)}, Remaining: remaining}, nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, err
}

func splitHeaderTokens(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseTransferEncoding(v string) string {
	// Only allow exactly "chunked" (case-insensitive) possibly with whitespace.
	parts := splitHeaderTokens(v)
	if len(parts) != 1 {
		return ""
	}
	return strings.ToLower(parts[0])
}

func decodeChunked(buf []byte, maxBody int) (decoded []byte, consumed int, complete bool, err error) {
	// decode chunks and return decoded bytes, and consumed bytes from buf
	out := make([]byte, 0, 1024)
	off := 0
	for {
		lineEnd := bytes.Index(buf[off:], []byte("\r\n"))
		if lineEnd == -1 {
			return nil, 0, false, nil
		}
		line := string(buf[off : off+lineEnd])
		off += lineEnd + 2
		// ignore chunk extensions
		if semi := strings.Index(line, ";"); semi != -1 {
			line = line[:semi]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return nil, 0, false, NewHttpRequestBlockedError("invalid chunk size", 400, "Bad Request")
		}
		size64, e := strconv.ParseInt(line, 16, 64)
		if e != nil || size64 < 0 {
			return nil, 0, false, NewHttpRequestBlockedError("invalid chunk size", 400, "Bad Request")
		}
		size := int(size64)
		if size == 0 {
			// Expect trailers terminated by CRLF.
			// We already consumed the 0-size line and its CRLF.
			trailersEnd := bytes.Index(buf[off:], []byte("\r\n\r\n"))
			if trailersEnd == -1 {
				// Could be just "\r\n" (no trailers). If buffer begins with CRLF, consume it.
				if len(buf[off:]) >= 2 && bytes.Equal(buf[off:off+2], []byte("\r\n")) {
					off += 2
					return out, off, true, nil
				}
				return nil, 0, false, nil
			}
			off += trailersEnd + 4
			return out, off, true, nil
		}
		if off+size+2 > len(buf) {
			return nil, 0, false, nil
		}
		out = append(out, buf[off:off+size]...)
		off += size
		if len(out) > maxBody {
			return nil, 0, false, NewHttpRequestBlockedError("payload too large", 413, "Payload Too Large")
		}
		if buf[off] != '\r' || buf[off+1] != '\n' {
			return nil, 0, false, NewHttpRequestBlockedError("invalid chunk framing", 400, "Bad Request")
		}
		off += 2
	}
}

// -------------------- Hop-by-hop headers --------------------

var hopByHopHeaders = map[string]struct{}{
	"connection":       {},
	"keep-alive":       {},
	"proxy-connection": {},
	"transfer-encoding": {},
	"te":               {},
	"trailer":          {},
	"upgrade":          {},
}

func (b *QemuNetworkBackend) stripHopByHopHeaders(headers map[string]string) map[string]string {
	out := map[string]string{}

	// Determine extra headers nominated by Connection.
	nominated := map[string]struct{}{}
	if c, ok := headers["connection"]; ok {
		for _, tok := range splitHeaderTokens(c) {
			if tok == "" {
				continue
			}
			nominated[strings.ToLower(tok)] = struct{}{}
		}
	}

	for k, v := range headers {
		lk := strings.ToLower(k)
		if _, ok := hopByHopHeaders[lk]; ok {
			continue
		}
		if _, ok := nominated[lk]; ok {
			continue
		}
		out[lk] = v
	}

	return out
}

// -------------------- HTTP ingestion --------------------

type httpSession struct {
	Buf          []byte
	Closed       bool
	SentContinue bool
}

type TcpIngressSession struct {
	HTTP *httpSession
}

type httpWriter struct {
	scheme string
	write  func(chunk []byte)
	finish func()
}

func (w httpWriter) Scheme() string { return w.scheme }
func (w httpWriter) Write(chunk []byte) { w.write(chunk) }
func (w httpWriter) Finish() { w.finish() }

func (b *QemuNetworkBackend) handleHttpDataWithWriter(key string, session *TcpIngressSession, data []byte, w httpWriter) error {
	if session.HTTP == nil {
		session.HTTP = &httpSession{}
	}
	h := session.HTTP
	if h.Closed {
		return nil
	}

	h.Buf = append(h.Buf, data...)

	parsed, err := b.parseHttpRequest(h.Buf)
	if err != nil {
		b.writeBlockedResponse(w, "HTTP/1.1", err)
		h.Closed = true
		w.Finish()
		return nil
	}
	if parsed == nil {
		// incomplete; if Expect: 100-continue and body pending, send 100 continue once.
		if !h.SentContinue {
			headerEnd := bytes.Index(h.Buf, []byte("\r\n\r\n"))
			if headerEnd != -1 {
				head := h.Buf[:headerEnd]
				_, hdrs, perr := parseRequestLineAndHeaders(head)
				if perr == nil {
					if exp, ok := hdrs["expect"]; ok && strings.EqualFold(strings.TrimSpace(exp), "100-continue") {
						bodyPending := false
						if te, ok := hdrs["transfer-encoding"]; ok {
							if parseTransferEncoding(te) == "chunked" {
								bodyPending = true
							}
						} else if cl := hdrs["content-length"]; cl != "" {
							if n, e := strconv.Atoi(strings.TrimSpace(cl)); e == nil && n > 0 {
								bodyPending = true
							}
						}
						if bodyPending {
							w.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n"))
							h.SentContinue = true
						}
					}
				}
			}
		}
		return nil
	}

	// parsed request
	if len(parsed.Remaining) > MAX_HTTP_PIPELINE_BYTES {
		b.writeSimpleResponse(w, parsed.Request.Version, 413, "Payload Too Large", map[string][]string{"content-length": {"0"}}, nil)
		h.Closed = true
		w.Finish()
		return nil
	}

	// For now, we don't implement full keep-alive; close after one request.
	_ = b.fetchAndRespond(parsed.Request, w.Scheme(), w.Write)
		h.Closed = true
		w.Finish()
	return nil
}

func parseRequestLineAndHeaders(headerBlock []byte) (line string, headers map[string]string, err error) {
	lines := strings.Split(string(headerBlock), "\r\n")
	if len(lines) == 0 {
		return "", nil, errors.New("empty header block")
	}
	l := lines[0]
	h := map[string]string{}
	for _, ln := range lines[1:] {
		if ln == "" {
			break
		}
		idx := strings.Index(ln, ":")
		if idx == -1 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(ln[:idx]))
		value := strings.TrimSpace(ln[idx+1:])
		if prev, ok := h[name]; ok {
			h[name] = prev + ", " + value
		} else {
			h[name] = value
		}
	}
	return l, h, nil
}

func (b *QemuNetworkBackend) writeBlockedResponse(w httpWriter, version string, err error) {
	blocked := &HttpRequestBlockedError{Status: 500, StatusText: "Internal Server Error"}
	if be, ok := err.(*HttpRequestBlockedError); ok {
		blocked = be
	}
	b.writeSimpleResponse(w, version, blocked.Status, blocked.StatusText, map[string][]string{"content-length": {"0"}}, nil)
}

func (b *QemuNetworkBackend) writeSimpleResponse(w httpWriter, version string, status int, statusText string, headers map[string][]string, body []byte) {
	if version == "" {
		version = "HTTP/1.1"
	}
	if statusText == "" {
		statusText = "OK"
	}

	// Copy headers and force connection close
	outHeaders := map[string][]string{}
	for k, vals := range headers {
		outHeaders[strings.ToLower(k)] = append([]string(nil), vals...)
	}
	outHeaders["connection"] = []string{"close"}

	// If body is nil, treat as empty
	if body == nil {
		body = []byte{}
	}

	// Ensure content-length
	if _, ok := outHeaders["content-length"]; !ok {
		outHeaders["content-length"] = []string{strconv.Itoa(len(body))}
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %d %s\r\n", version, status, statusText)
	for k, vals := range outHeaders {
		for _, v := range vals {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	w.Write(buf.Bytes())
}

// -------------------- Fetch and respond --------------------

func (b *QemuNetworkBackend) defaultResolveHostname(hostname string) (string, int, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(nil, hostname)
	if err != nil || len(ips) == 0 {
		return "", 0, err
	}
	ip := ips[0].IP
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String(), 4, nil
	}
	return ip.String(), 6, nil
}

func (b *QemuNetworkBackend) ensureRequestAllowed(u *url.URL) error {
	if b.httpHooks.IsAllowed == nil {
		return nil
	}

	hostname := strings.ToLower(u.Hostname())
	portStr := u.Port()
	port := 0
	if portStr != "" {
		p, _ := strconv.Atoi(portStr)
		port = p
	} else {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	ip, family, err := b.resolveHostname(hostname)
	if err != nil {
		return NewHttpRequestBlockedError("dns lookup failed", 502, "Bad Gateway")
	}

	allowed, err := b.httpHooks.IsAllowed(HttpAllowInfo{Hostname: hostname, IP: ip, Family: family, Port: port, Protocol: u.Scheme})
	if err != nil {
		return err
	}
	if !allowed {
		return NewHttpRequestBlockedError("request blocked", 403, "Forbidden")
	}
	return nil
}

func (b *QemuNetworkBackend) fetchAndRespond(req *HttpRequestData, scheme string, write func([]byte)) error {
	version := req.Version
	if version == "" {
		version = "HTTP/1.1"
	}
	// Reject OPTIONS *
	if strings.EqualFold(req.Method, "OPTIONS") && req.Target == "*" {
		b.writeSimpleResponse(httpWriter{scheme: scheme, write: write, finish: func() {}}, version, 501, "Not Implemented", map[string][]string{"content-length": {"0"}}, nil)
		return nil
	}

	if isWebSocketUpgrade(req.Headers) {
		b.writeSimpleResponse(httpWriter{scheme: scheme, write: write, finish: func() {}}, version, 501, "Not Implemented", map[string][]string{"content-length": {"0"}}, nil)
		return nil
	}

	host := req.Headers["host"]
	if host == "" {
		return NewHttpRequestBlockedError("missing host", 400, "Bad Request")
	}

	baseURL := (&url.URL{Scheme: scheme, Host: host, Path: req.Target}).String()

	method := req.Method
	body := req.Body
	headers := b.stripHopByHopHeaders(req.Headers)

	redirects := 0
	currentURL := baseURL

	for {
		u, err := url.Parse(currentURL)
		if err != nil {
			return NewHttpRequestBlockedError("bad url", 400, "Bad Request")
		}
		if err := b.ensureRequestAllowed(u); err != nil {
			return err
		}

		// Apply request hook
		hookReq := HttpHookRequest{Method: method, URL: u.String(), Headers: cloneStringMap(headers), Body: body}
		if b.httpHooks.OnRequest != nil {
			updated, err := b.httpHooks.OnRequest(hookReq)
			if err != nil {
				return err
			}
			if updated != nil {
				hookReq = *updated
			}
		}

		init := HttpFetchInit{Method: hookReq.Method, Headers: hookReq.Headers, Body: hookReq.Body}
		resp, err := b.fetch(hookReq.URL, init)
		if err != nil {
			return NewHttpRequestBlockedError("upstream fetch failed", 502, "Bad Gateway")
		}

		// redirect?
		if isRedirect(resp.Status) {
			loc := firstHeader(resp.Headers, "location")
			if loc != "" {
				redirects++
				if redirects > maxHTTPRedirects {
					return NewHttpRequestBlockedError("too many redirects", 502, "Bad Gateway")
				}
				newURL := resolveRedirect(u, loc)
				// rewrite POST->GET for 301/302/303
				if (resp.Status == 301 || resp.Status == 302 || resp.Status == 303) && !strings.EqualFold(method, "GET") && !strings.EqualFold(method, "HEAD") {
					method = "GET"
					body = nil
					delete(headers, "content-length")
					delete(headers, "content-type")
					delete(headers, "transfer-encoding")
				}
				// update host header
				uu, _ := url.Parse(newURL)
				headers["host"] = uu.Host
				currentURL = newURL
				// close body
				if resp.Body != nil {
					_ = resp.Body.Close()
				}
				continue
			}
		}

		// Final response
		return b.writeFetchResponse(req, version, resp, write)
	}
}

func (b *QemuNetworkBackend) writeFetchResponse(request *HttpRequestData, version string, resp *HttpFetchResponse, write func([]byte)) error {
	statusText := resp.StatusText
	if statusText == "" {
		statusText = httpStatusText(resp.Status)
	}

	// Collect headers
	headers := cloneHeaderMap(resp.Headers)

	// Handle multiple Set-Cookie as-is.

	// Drop hop-by-hop response headers
	for k := range headers {
		lk := strings.ToLower(k)
		if _, ok := hopByHopHeaders[lk]; ok {
			delete(headers, k)
		}
	}

	// Determine if we must suppress body
	suppressBody := strings.EqualFold(request.Method, "HEAD") || resp.Status == 204 || resp.Status == 304

	if resp.Status == 204 || resp.Status == 304 {
		suppressBody = true
		// force content-length 0
		headers["content-length"] = []string{"0"}
	}

	// Response hook buffering
	if b.httpHooks.OnResponse != nil {
		// buffer body (respect cap)
		body, err := readAllWithLimit(resp.Body, b.maxHttpResponseBodyBytes)
		if err != nil {
			// cancel/close body
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			return NewHttpRequestBlockedError("response too large", 502, "Bad Gateway")
		}
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if suppressBody {
			body = []byte{}
		}

		hookResp := HttpHookResponse{Status: resp.Status, StatusText: statusText, Headers: headers, Body: body}
		hookReq := HttpHookRequest{Method: request.Method, URL: "", Headers: request.Headers, Body: request.Body}
		updated, err := b.httpHooks.OnResponse(hookResp, hookReq)
		if err != nil {
			return err
		}
		if updated != nil {
			hookResp = *updated
		}

		// Write buffered response
		outHeaders := cloneHeaderMap(hookResp.Headers)
		outHeaders["content-length"] = []string{strconv.Itoa(len(hookResp.Body))}
		b.writeRawResponse(version, hookResp.Status, hookResp.StatusText, outHeaders, hookResp.Body, write)
		return nil
	}

	// No response hook: stream when unknown length or encoded.
	encoded := firstHeader(headers, "content-encoding") != ""
	contentLen := firstHeader(headers, "content-length")

	if suppressBody {
		// keep content-length if provided for HEAD, otherwise set 0
		body := []byte{}
		if request.Method != "HEAD" {
			headers["content-length"] = []string{"0"}
		}
		b.writeRawResponse(version, resp.Status, statusText, headers, body, write)
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil
	}

	if version == "HTTP/1.0" && (encoded || contentLen == "") {
		// HTTP/1.0: no chunked, buffer body
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		delete(headers, "content-encoding")
		headers["content-length"] = []string{strconv.Itoa(len(body))}
		b.writeRawResponse(version, resp.Status, statusText, headers, body, write)
		return nil
	}

	if encoded || contentLen == "" {
		// Stream chunked for HTTP/1.1
		delete(headers, "content-encoding")
		delete(headers, "content-length")
		headers["transfer-encoding"] = []string{"chunked"}
		b.writeRawResponseHeader(version, resp.Status, statusText, headers, write)
		// chunked body
		br := bufio.NewReader(resp.Body)
		buf := make([]byte, 8192)
		for {
			n, err := br.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				write([]byte(fmt.Sprintf("%x\r\n", len(chunk))))
				write(chunk)
				write([]byte("\r\n"))
			}
			if err != nil {
				break
			}
		}
		write([]byte("0\r\n\r\n"))
		_ = resp.Body.Close()
		return nil
	}

	// Known length: buffer and send
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	b.writeRawResponse(version, resp.Status, statusText, headers, body, write)
	return nil
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

func resolveRedirect(base *url.URL, location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return location
	}
	return base.ResolveReference(u).String()
}

func cloneStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneHeaderMap(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[strings.ToLower(k)] = append([]string(nil), v...)
	}
	return out
}

func firstHeader(headers map[string][]string, name string) string {
	vals := headers[strings.ToLower(name)]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func isWebSocketUpgrade(headers map[string]string) bool {
	conn := strings.ToLower(headers["connection"])
	up := strings.ToLower(headers["upgrade"])
	if strings.Contains(conn, "upgrade") && up == "websocket" {
		return true
	}
	return false
}

func httpStatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 204:
		return "No Content"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 403:
		return "Forbidden"
	case 413:
		return "Payload Too Large"
	case 417:
		return "Expectation Failed"
	case 431:
		return "Request Header Fields Too Large"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	default:
		return "" + strconv.Itoa(code)
	}
}

func (b *QemuNetworkBackend) writeRawResponse(version string, status int, statusText string, headers map[string][]string, body []byte, write func([]byte)) {
	b.writeRawResponseHeader(version, status, statusText, headers, write)
	if body != nil {
		write(body)
	}
}

func (b *QemuNetworkBackend) writeRawResponseHeader(version string, status int, statusText string, headers map[string][]string, write func([]byte)) {
	if version == "" {
		version = "HTTP/1.1"
	}
	if statusText == "" {
		statusText = httpStatusText(status)
	}

	// Force connection close
	headers = cloneHeaderMap(headers)
	headers["connection"] = []string{"close"}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %d %s\r\n", version, status, statusText)
	for k, vals := range headers {
		for _, v := range vals {
			fmt.Fprintf(&buf, "%s: %s\r\n", strings.ToLower(k), v)
		}
	}
	buf.WriteString("\r\n")
	write(buf.Bytes())
}

func readAllWithLimit(body io.ReadCloser, max int) ([]byte, error) {
	if body == nil {
		return []byte{}, nil
	}
	defer func() {
		// caller closes explicitly
	}()

	var out bytes.Buffer
	buf := make([]byte, 8192)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if out.Len()+n > max {
				return nil, errors.New("limit exceeded")
			}
			out.Write(buf[:n])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
	}
	return out.Bytes(), nil
}

// -------------------- DNS handling --------------------

func (b *QemuNetworkBackend) pickTrustedDnsServer() (string, error) {
	if len(b.trustedDnsServers) == 0 {
		return "", fmt.Errorf("dns mode 'trusted' requires at least one IPv4 resolver (none configured/found)")
	}
	idx := b.trustedDnsIndex % len(b.trustedDnsServers)
	b.trustedDnsIndex++
	return b.trustedDnsServers[idx], nil
}

func (b *QemuNetworkBackend) HandleUdpSend(msg UdpSendMessage) {
	// Only handle DNS
	if msg.DstPort != 53 {
		return
	}

	if b.dnsMode == DnsModeSynthetic {
		b.handleSyntheticDns(msg)
		return
	}

	// trusted mode blocks non-dns payloads
	if b.dnsMode == DnsModeTrusted {
		if gondolindns.ParseDnsQuery(msg.Payload) == nil {
			return
		}
	}

	sess := b.udpSessions[msg.Key]
	if sess == nil {
		factory := b.options.UdpSocketFactory
		if factory == nil {
			// default implementation using net.UDPConn
			factory = func() UdpSocket { return newUdpSocketImpl() }
		}
		socket := factory()

		upstreamIP := msg.DstIP
		if b.dnsMode == DnsModeTrusted {
			picked, err := b.pickTrustedDnsServer()
			if err != nil {
				return
			}
			upstreamIP = picked
		}

		sess = &udpSession{
			Socket: socket,
			SrcIP: msg.SrcIP,
			SrcPort: msg.SrcPort,
			DstIP: msg.DstIP,
			DstPort: msg.DstPort,
			UpstreamIP: upstreamIP,
			UpstreamPort: 53,
		}
		b.udpSessions[msg.Key] = sess

		socket.SetOnMessage(func(data []byte, _addr string, _port int) {
			if b.stackUdp != nil {
				b.stackUdp.HandleUdpResponse(map[string]any{
					"data": append([]byte(nil), data...),
					"srcIP": sess.SrcIP,
					"srcPort": sess.SrcPort,
					"dstIP": sess.DstIP,
					"dstPort": sess.DstPort,
				})
			}
		})
		socket.SetOnError(func(_ error) {})
	}

	sess.Socket.Send(msg.Payload, sess.UpstreamPort, sess.UpstreamIP)
}

type UdpSendMessage struct {
	Key     string
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	Payload []byte
}

func (b *QemuNetworkBackend) handleSyntheticDns(msg UdpSendMessage) {
	if !gondolindns.IsProbablyDnsPacket(msg.Payload) {
		return
	}
	query := gondolindns.ParseDnsQuery(msg.Payload)
	if query == nil {
		return
	}
	resp := gondolindns.BuildSyntheticDnsResponse(query, b.syntheticDnsOpts)
	if b.stackUdp != nil {
		b.stackUdp.HandleUdpResponse(map[string]any{
			"data": resp,
			"srcIP": msg.SrcIP,
			"srcPort": msg.SrcPort,
			"dstIP": msg.DstIP,
			"dstPort": msg.DstPort,
		})
	}
}

// -------------------- TCP pending write cap --------------------

func (b *QemuNetworkBackend) HandleTcpSend(key string, data []byte) {
	sess := b.tcpSessions[key]
	if sess == nil {
		return
	}
	if sess.PendingWriteBytes+len(data) > b.maxTcpPendingWriteBytes {
		if b.stackTcp != nil {
			b.stackTcp.HandleTcpError(key)
		}
		delete(b.tcpSessions, key)
		return
	}

	copyData := append([]byte(nil), data...)
	sess.PendingWrites = append(sess.PendingWrites, copyData)
	sess.PendingWriteBytes += len(copyData)
}

// -------------------- Lookup guard --------------------

type LookupFunc func(hostname string, options any, cb func(err error, address any, family int))

type LookupInfo struct {
	Hostname string
	Port     int
	Protocol string
}

func CreateLookupGuard(target LookupInfo, isAllowed func(info HttpAllowInfo) (bool, error), lookup LookupFunc) LookupFunc {
	return func(hostname string, options any, cb func(err error, address any, family int)) {
		lookup(hostname, options, func(err error, address any, family int) {
			if err != nil {
				cb(err, nil, 0)
				return
			}

			// options may be map with {all:true}
			all := false
			switch o := options.(type) {
			case map[string]any:
				if v, ok := o["all"].(bool); ok && v {
					all = true
				}
			}

			if !all {
				ipStr := ""
				switch v := address.(type) {
				case string:
					ipStr = v
				case map[string]any:
					if s, ok := v["address"].(string); ok {
						ipStr = s
					}
				}
				allowed, _ := isAllowed(HttpAllowInfo{Hostname: target.Hostname, IP: ipStr, Family: family, Port: target.Port, Protocol: target.Protocol})
				if !allowed {
					cb(NewHttpRequestBlockedError("request blocked", 403, "Forbidden"), nil, 0)
					return
				}
				cb(nil, address, family)
				return
			}

			// all=true: expect slice of {address,family}
			arr, ok := address.([]any)
			if !ok {
				cb(nil, address, family)
				return
			}
			filtered := make([]any, 0, len(arr))
			for _, entry := range arr {
				m, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				addr, _ := m["address"].(string)
				famAny := m["family"]
				fam := 0
				switch x := famAny.(type) {
				case int:
					fam = x
				case float64:
					fam = int(x)
				}
				allowed, _ := isAllowed(HttpAllowInfo{Hostname: target.Hostname, IP: addr, Family: fam, Port: target.Port, Protocol: target.Protocol})
				if allowed {
					filtered = append(filtered, map[string]any{"address": addr, "family": fam})
				}
			}
			if len(filtered) == 0 {
				cb(NewHttpRequestBlockedError("request blocked", 403, "Forbidden"), nil, 0)
				return
			}
			cb(nil, filtered, family)
		})
	}
}

// -------------------- TLS MITM cert generation and caching --------------------

func (b *QemuNetworkBackend) getTlsContextAsync(servername string) (*tls.Config, error) {
	// ttl <= 0 disables caching: clear on each access.
	if b.tlsCacheTtl <= 0 {
		b.tlsCacheMu.Lock()
		b.tlsCache = map[string]*list.Element{}
		b.tlsLru = list.New()
		b.tlsCacheMu.Unlock()
	}

	// Try cache
	if b.tlsCacheTtl > 0 {
		b.tlsCacheMu.Lock()
		if el, ok := b.tlsCache[servername]; ok {
			ent := el.Value.(*tlsCacheEntry)
			if time.Since(ent.LastAccess) <= b.tlsCacheTtl {
				ent.LastAccess = time.Now()
				b.tlsLru.MoveToBack(el)
				cfg := ent.Config
				b.tlsCacheMu.Unlock()
				return cfg, nil
			}
			// expired
			b.tlsLru.Remove(el)
			delete(b.tlsCache, servername)
		}
		b.tlsCacheMu.Unlock()
	}

	cfg, err := b.createTlsContext(servername)
	if err != nil {
		return nil, err
	}

	b.tlsCacheMu.Lock()
	// insert
	ent := &tlsCacheEntry{Servername: servername, Config: cfg, LastAccess: time.Now()}
	el := b.tlsLru.PushBack(ent)
	b.tlsCache[servername] = el

	// enforce LRU size
	for b.tlsLru.Len() > b.tlsCacheMaxEntries {
		front := b.tlsLru.Front()
		if front == nil {
			break
		}
		victim := front.Value.(*tlsCacheEntry)
		delete(b.tlsCache, victim.Servername)
		b.tlsLru.Remove(front)
	}
	b.tlsCacheMu.Unlock()

	return cfg, nil
}

func (b *QemuNetworkBackend) defaultCreateTlsContext(servername string) (*tls.Config, error) {
	// Ensure CA exists
	b.mitmMu.Lock()
	if b.mitmCa == nil {
		ca, err := mitm.LoadOrCreateMitmCa(b.mitmCertDir)
		if err != nil {
			b.mitmMu.Unlock()
			return nil, err
		}
		b.mitmCa = ca
	}
	ca := b.mitmCa
	b.mitmMu.Unlock()

	hostsDir := filepath.Join(b.mitmCertDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		return nil, err
	}

	// stable filename based on sha256(host)
	h := sha256.Sum256([]byte(strings.ToLower(servername)))
	base := hex.EncodeToString(h[:8])
	crtPath := filepath.Join(hostsDir, base+".crt")
	keyPath := filepath.Join(hostsDir, base+".key")

	// Reuse on disk if present
	if cert, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	// Generate leaf key
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)

	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{CommonName: servername},
		NotBefore: notBefore,
		NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{servername},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &leafKey.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}

	leafKeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	leafCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	// Write to disk
	_ = os.WriteFile(keyPath, leafKeyPem, 0o600)
	_ = os.WriteFile(crtPath, leafCertPem, 0o644)

	cert, err := tls.X509KeyPair(leafCertPem, leafKeyPem)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}


// -------------------- UDP socket impl --------------------

type udpSocketImpl struct {
	conn *net.UDPConn
	onMessage func(data []byte, addr string, port int)
	onError func(error)
}

func newUdpSocketImpl() *udpSocketImpl {
	// We create an unbound UDP socket.
	conn, _ := net.ListenUDP("udp4", nil)
	s := &udpSocketImpl{conn: conn}
	go s.readLoop()
	return s
}

func (s *udpSocketImpl) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if s.onError != nil {
				s.onError(err)
			}
			return
		}
		if s.onMessage != nil {
			s.onMessage(append([]byte(nil), buf[:n]...), addr.IP.String(), addr.Port)
		}
	}
}

func (s *udpSocketImpl) Send(buf []byte, port int, address string) {
	addr := &net.UDPAddr{IP: net.ParseIP(address), Port: port}
	_, _ = s.conn.WriteToUDP(buf, addr)
}

func (s *udpSocketImpl) Close() {
	_ = s.conn.Close()
}

func (s *udpSocketImpl) SetOnMessage(fn func(data []byte, address string, port int)) {
	s.onMessage = fn
}

func (s *udpSocketImpl) SetOnError(fn func(err error)) {
	s.onError = fn
}
