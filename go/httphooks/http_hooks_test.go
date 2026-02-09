package httphooks

import (
	"testing"

	"github.com/earendil-works/gondolin-go/qemunet"
)

func TestHttpHooksAllowlistPatterns(t *testing.T) {
	res, err := CreateHttpHooks(CreateHttpHooksOptions{AllowedHosts: []string{"example.com", "*.example.org", "api.*.net"}})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}
	isAllowed := res.HttpHooks.IsAllowed

	ok, _ := isAllowed(qemunet.HttpAllowInfo{Hostname: "example.com", IP: "8.8.8.8", Family: 4, Port: 443, Protocol: "https"})
	if !ok {
		t.Fatalf("expected allowed")
	}

	ok, _ = isAllowed(qemunet.HttpAllowInfo{Hostname: "Foo.Example.Org", IP: "1.1.1.1", Family: 4, Port: 80, Protocol: "http"})
	if !ok {
		t.Fatalf("expected allowed")
	}

	ok, _ = isAllowed(qemunet.HttpAllowInfo{Hostname: "api.foo.net", IP: "93.184.216.34", Family: 4, Port: 443, Protocol: "https"})
	if !ok {
		t.Fatalf("expected allowed")
	}

	ok, _ = isAllowed(qemunet.HttpAllowInfo{Hostname: "nope.com", IP: "93.184.216.34", Family: 4, Port: 443, Protocol: "https"})
	if ok {
		t.Fatalf("expected denied")
	}
}

func TestHttpHooksHostnameMatchingHandlesEmptyAndMultipleWildcards(t *testing.T) {
	res, err := CreateHttpHooks(CreateHttpHooksOptions{AllowedHosts: []string{"", "   ", "a**b.com"}})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}
	if len(res.AllowedHosts) != 1 || res.AllowedHosts[0] != "a**b.com" {
		t.Fatalf("unexpected allowedHosts: %v", res.AllowedHosts)
	}

	isAllowed := res.HttpHooks.IsAllowed

	cases := []string{"axxxb.com", "ab.com", "acb.com"}
	for _, host := range cases {
		ok, _ := isAllowed(qemunet.HttpAllowInfo{Hostname: host, IP: "8.8.8.8", Family: 4, Port: 443, Protocol: "https"})
		if !ok {
			t.Fatalf("expected %s allowed", host)
		}
	}

	ok, _ := isAllowed(qemunet.HttpAllowInfo{Hostname: "nope.com", IP: "8.8.8.8", Family: 4, Port: 443, Protocol: "https"})
	if ok {
		t.Fatalf("expected denied")
	}
}

func TestHttpHooksAllowlistStarMatchesAnyButStillBlocksInternal(t *testing.T) {
	res, err := CreateHttpHooks(CreateHttpHooksOptions{AllowedHosts: []string{"*"}})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}

	isAllowed := res.HttpHooks.IsAllowed

	ok, _ := isAllowed(qemunet.HttpAllowInfo{Hostname: "anything.example", IP: "8.8.8.8", Family: 4, Port: 443, Protocol: "https"})
	if !ok {
		t.Fatalf("expected allowed")
	}

	ok, _ = isAllowed(qemunet.HttpAllowInfo{Hostname: "anything.example", IP: "::1", Family: 6, Port: 443, Protocol: "https"})
	if ok {
		t.Fatalf("expected internal blocked")
	}
}

func TestHttpHooksBlockInternalRangesByDefault(t *testing.T) {
	res, err := CreateHttpHooks(CreateHttpHooksOptions{AllowedHosts: []string{"example.com"}})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}

	ok, _ := res.HttpHooks.IsAllowed(qemunet.HttpAllowInfo{Hostname: "example.com", IP: "10.0.0.1", Family: 4, Port: 80, Protocol: "http"})
	if ok {
		t.Fatalf("expected blocked")
	}
}

func TestHttpHooksBlockInternalIPv6Ranges(t *testing.T) {
	res, err := CreateHttpHooks(CreateHttpHooksOptions{AllowedHosts: []string{"example.com"}})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}

	cases := []string{"::", "::1", "fc00::1", "fd12:3456:789a::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"}
	for _, ip := range cases {
		ok, _ := res.HttpHooks.IsAllowed(qemunet.HttpAllowInfo{Hostname: "example.com", IP: ip, Family: 6, Port: 443, Protocol: "https"})
		if ok {
			t.Fatalf("expected %s blocked", ip)
		}
	}
}

func TestHttpHooksAllowNonPrivateIPv6(t *testing.T) {
	res, err := CreateHttpHooks(CreateHttpHooksOptions{AllowedHosts: []string{"example.com"}})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}

	ok, _ := res.HttpHooks.IsAllowed(qemunet.HttpAllowInfo{Hostname: "example.com", IP: "::ffff:8.8.8.8", Family: 6, Port: 443, Protocol: "https"})
	if !ok {
		t.Fatalf("expected allowed")
	}

	ok, _ = res.HttpHooks.IsAllowed(qemunet.HttpAllowInfo{Hostname: "example.com", IP: "64:ff9b::8.8.8.8", Family: 6, Port: 443, Protocol: "https"})
	if !ok {
		t.Fatalf("expected allowed")
	}
}

func TestHttpHooksIgnoreInvalidIpStringsForInternalChecks(t *testing.T) {
	res, err := CreateHttpHooks(CreateHttpHooksOptions{AllowedHosts: []string{"example.com"}})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}

	ok, _ := res.HttpHooks.IsAllowed(qemunet.HttpAllowInfo{Hostname: "example.com", IP: "zzzz::1", Family: 6, Port: 443, Protocol: "https"})
	if !ok {
		t.Fatalf("expected allowed")
	}
}

func TestHttpHooksCanAllowInternalRanges(t *testing.T) {
	block := false
	res, err := CreateHttpHooks(CreateHttpHooksOptions{AllowedHosts: []string{"example.com"}, BlockInternalRanges: &block})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}

	ok, _ := res.HttpHooks.IsAllowed(qemunet.HttpAllowInfo{Hostname: "example.com", IP: "10.0.0.1", Family: 4, Port: 80, Protocol: "http"})
	if !ok {
		t.Fatalf("expected allowed")
	}
}

func TestHttpHooksReplaceSecretPlaceholders(t *testing.T) {
	res, err := CreateHttpHooks(CreateHttpHooksOptions{Secrets: map[string]SecretDefinition{"API_KEY": {Hosts: []string{"example.com"}, Value: "secret-value"}}})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}

	if len(res.AllowedHosts) == 0 {
		t.Fatalf("expected allowed hosts")
	}

	req := qemunet.HttpHookRequest{Method: "GET", URL: "https://example.com/data", Headers: map[string]string{"authorization": "Bearer " + res.Env["API_KEY"]}, Body: nil}
	updated, err := res.HttpHooks.OnRequest(req)
	if err != nil {
		t.Fatalf("onRequest: %v", err)
	}
	if updated == nil {
		t.Fatalf("expected updated")
	}
	if updated.Headers["authorization"] != "Bearer secret-value" {
		t.Fatalf("expected secret replacement")
	}
}

func TestHttpHooksRejectSecretsOnDisallowedHosts(t *testing.T) {
	res, err := CreateHttpHooks(CreateHttpHooksOptions{Secrets: map[string]SecretDefinition{"API_KEY": {Hosts: []string{"example.com"}, Value: "secret-value"}}})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}

	req := qemunet.HttpHookRequest{Method: "GET", URL: "https://example.org/data", Headers: map[string]string{"authorization": "Bearer " + res.Env["API_KEY"]}, Body: nil}
	_, err = res.HttpHooks.OnRequest(req)
	if err == nil {
		t.Fatalf("expected error")
	}
	if _, ok := err.(*qemunet.HttpRequestBlockedError); !ok {
		t.Fatalf("expected blocked error, got %T", err)
	}
}

func TestHttpHooksPassThroughCustomHandler(t *testing.T) {
	seenAuth := make([]string, 0, 1)
	res, err := CreateHttpHooks(CreateHttpHooksOptions{
		Secrets: map[string]SecretDefinition{"API_KEY": {Hosts: []string{"example.com"}, Value: "secret-value"}},
		OnRequest: func(req qemunet.HttpHookRequest) (*qemunet.HttpHookRequest, error) {
			seenAuth = append(seenAuth, req.Headers["authorization"])
			req.Headers["x-extra"] = "1"
			return &req, nil
		},
	})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}

	req := qemunet.HttpHookRequest{Method: "POST", URL: "https://example.com/data", Headers: map[string]string{"authorization": "Bearer " + res.Env["API_KEY"]}, Body: nil}
	updated, err := res.HttpHooks.OnRequest(req)
	if err != nil {
		t.Fatalf("onRequest: %v", err)
	}
	if len(seenAuth) != 1 || seenAuth[0] != "Bearer secret-value" {
		t.Fatalf("unexpected seenAuth: %v", seenAuth)
	}
	if updated.Headers["authorization"] != "Bearer secret-value" {
		t.Fatalf("expected replaced auth")
	}
	if updated.Headers["x-extra"] != "1" {
		t.Fatalf("expected x-extra")
	}
}

func TestHttpHooksPreserveRequestWhenHandlerReturnsNil(t *testing.T) {
	seenAuth := make([]string, 0, 1)
	res, err := CreateHttpHooks(CreateHttpHooksOptions{
		Secrets: map[string]SecretDefinition{"API_KEY": {Hosts: []string{"example.com"}, Value: "secret-value"}},
		OnRequest: func(req qemunet.HttpHookRequest) (*qemunet.HttpHookRequest, error) {
			seenAuth = append(seenAuth, req.Headers["authorization"])
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("CreateHttpHooks: %v", err)
	}

	req := qemunet.HttpHookRequest{Method: "POST", URL: "https://example.com/data", Headers: map[string]string{"authorization": "Bearer " + res.Env["API_KEY"]}, Body: nil}
	updated, err := res.HttpHooks.OnRequest(req)
	if err != nil {
		t.Fatalf("onRequest: %v", err)
	}
	if len(seenAuth) != 1 || seenAuth[0] != "Bearer secret-value" {
		t.Fatalf("unexpected seenAuth: %v", seenAuth)
	}
	if updated.Headers["authorization"] != "Bearer secret-value" {
		t.Fatalf("expected replaced auth")
	}
}
