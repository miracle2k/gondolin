package httphooks

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/earendil-works/gondolin-go/qemunet"
)

type SecretDefinition struct {
	Hosts []string
	Value string
}

type CreateHttpHooksOptions struct {
	/** allowed host patterns (empty = allow all) */
	AllowedHosts []string
	/** secret definitions keyed by env var name */
	Secrets map[string]SecretDefinition
	/** whether to block internal ip ranges (default: true) */
	BlockInternalRanges *bool
	/** custom allow callback (invoked after default checks) */
	IsAllowed func(info qemunet.HttpAllowInfo) (bool, error)
	/** request hook */
	OnRequest func(req qemunet.HttpHookRequest) (*qemunet.HttpHookRequest, error)
	/** response hook */
	OnResponse func(resp qemunet.HttpHookResponse, req qemunet.HttpHookRequest) (*qemunet.HttpHookResponse, error)
}

type CreateHttpHooksResult struct {
	HttpHooks    qemunet.HttpHooks
	Env          map[string]string
	AllowedHosts []string
}

type secretEntry struct {
	Name        string
	Placeholder string
	Value       string
	Hosts       []string
}

func CreateHttpHooks(options CreateHttpHooksOptions) (CreateHttpHooksResult, error) {
	env := map[string]string{}
	secretEntries := make([]secretEntry, 0)

	blockInternal := true
	if options.BlockInternalRanges != nil {
		blockInternal = *options.BlockInternalRanges
	}

	for name, secret := range options.Secrets {
		placeholder, err := randomPlaceholder()
		if err != nil {
			return CreateHttpHooksResult{}, err
		}
		env[name] = placeholder
		hosts := make([]string, 0, len(secret.Hosts))
		for _, h := range secret.Hosts {
			h = normalizeHostnamePattern(h)
			if h != "" {
				hosts = append(hosts, h)
			}
		}
		secretEntries = append(secretEntries, secretEntry{
			Name:        name,
			Placeholder: placeholder,
			Value:       secret.Value,
			Hosts:       hosts,
		})
	}

	allowedHosts := uniqueHosts(append(append([]string{}, options.AllowedHosts...), flattenHosts(secretEntries)...))

	hooks := qemunet.HttpHooks{}

	hooks.IsAllowed = func(info qemunet.HttpAllowInfo) (bool, error) {
		if blockInternal && isInternalAddress(info.IP) {
			return false, nil
		}
		if len(allowedHosts) > 0 {
			if !matchesAnyHost(info.Hostname, allowedHosts) {
				return false, nil
			}
		}
		if options.IsAllowed != nil {
			return options.IsAllowed(info)
		}
		return true, nil
	}

	hooks.OnRequest = func(req qemunet.HttpHookRequest) (*qemunet.HttpHookRequest, error) {
		hostname := getHostname(req)
		headers, err := replaceSecretPlaceholders(req.Headers, hostname, secretEntries)
		if err != nil {
			return nil, err
		}
		next := qemunet.HttpHookRequest{Method: req.Method, URL: req.URL, Headers: headers, Body: req.Body}

		if options.OnRequest != nil {
			updated, err := options.OnRequest(next)
			if err != nil {
				return nil, err
			}
			if updated != nil {
				next = *updated
			}
		}

		return &next, nil
	}

	hooks.OnResponse = options.OnResponse

	return CreateHttpHooksResult{HttpHooks: hooks, Env: env, AllowedHosts: allowedHosts}, nil
}

func randomPlaceholder() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "GONDOLIN_SECRET_" + hex.EncodeToString(b), nil
}

func flattenHosts(entries []secretEntry) []string {
	out := make([]string, 0)
	for _, e := range entries {
		out = append(out, e.Hosts...)
	}
	return out
}

func getHostname(req qemunet.HttpHookRequest) string {
	u, err := url.Parse(req.URL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func replaceSecretPlaceholders(headers map[string]string, hostname string, entries []secretEntry) (map[string]string, error) {
	if len(entries) == 0 {
		return headers, nil
	}

	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[k] = v
	}

	for hk, hv := range out {
		updated := hv
		for _, entry := range entries {
			if !strings.Contains(updated, entry.Placeholder) {
				continue
			}
			if !matchesAnyHost(hostname, entry.Hosts) {
				return nil, qemunet.NewHttpRequestBlockedError("secret "+entry.Name+" not allowed for host: "+hostname, 403, "Forbidden")
			}
			updated = strings.ReplaceAll(updated, entry.Placeholder, entry.Value)
		}
		out[hk] = updated
	}

	return out, nil
}

func uniqueHosts(hosts []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = normalizeHostnamePattern(h)
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

func normalizeHostnamePattern(pattern string) string {
	return strings.ToLower(strings.TrimSpace(pattern))
}

func matchesAnyHost(hostname string, patterns []string) bool {
	hostname = strings.ToLower(hostname)
	for _, p := range patterns {
		if matchHostname(hostname, p) {
			return true
		}
	}
	return false
}

func matchHostname(hostname string, pattern string) bool {
	pattern = normalizeHostnamePattern(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}

	parts := strings.Split(pattern, "*")
	quoted := make([]string, 0, len(parts))
	for _, part := range parts {
		quoted = append(quoted, regexp.QuoteMeta(part))
	}
	re := "^" + strings.Join(quoted, ".*") + "$"
	return regexp.MustCompile(re).MatchString(hostname)
}

func isInternalAddress(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return isPrivateIPv4(v4)
	}
	// IPv6
	v16 := ip.To16()
	if v16 == nil {
		return false
	}
	return isPrivateIPv6(v16)
}

func isPrivateIPv4(ip net.IP) bool {
	if len(ip) != 4 {
		return false
	}
	a, b := ip[0], ip[1]
	if a == 0 {
		return true
	}
	if a == 10 {
		return true
	}
	if a == 127 {
		return true
	}
	if a == 169 && b == 254 {
		return true
	}
	if a == 172 && b >= 16 && b <= 31 {
		return true
	}
	if a == 192 && b == 168 {
		return true
	}
	if a == 100 && b >= 64 && b <= 127 {
		return true
	}
	if a == 255 {
		return true
	}
	return false
}

func isPrivateIPv6(ip net.IP) bool {
	if len(ip) != 16 {
		return false
	}

	allZero := true
	for _, b := range ip {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return true
	}

	if ip.Equal(net.IPv6loopback) {
		return true
	}

	// ULA fc00::/7
	if (ip[0] & 0xfe) == 0xfc {
		return true
	}

	// link-local fe80::/10
	if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true
	}

	// IPv4-mapped ::ffff:w.x.y.z
	mapped := isIPv4Mapped(ip)
	if mapped != nil {
		return isPrivateIPv4(mapped)
	}

	return false
}

func isIPv4Mapped(ip net.IP) net.IP {
	if len(ip) != 16 {
		return nil
	}
	for i := 0; i < 10; i++ {
		if ip[i] != 0 {
			return nil
		}
	}
	if ip[10] != 0xff || ip[11] != 0xff {
		return nil
	}
	return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
}
