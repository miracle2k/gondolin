package vfs

import (
	"path"
	"strings"
)

// IsWriteFlag returns true if the open flag implies a write operation.
func IsWriteFlag(flags string) bool {
	// Matches Node-style flag strings: w, w+, a, a+, r+
	return strings.ContainsAny(flags, "wa+") || strings.Contains(flags, "r+")
}

// NormalizeVfsPath normalizes an absolute POSIX path used by the VFS layer.
func NormalizeVfsPath(input string) string {
	n := path.Clean(input)
	if !strings.HasPrefix(n, "/") {
		n = "/" + n
	}
	if n != "/" && strings.HasSuffix(n, "/") {
		n = strings.TrimSuffix(n, "/")
	}
	return n
}
