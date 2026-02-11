package sandbox

import "testing"

func TestBuildSandboxfsAppend(t *testing.T) {
	base := "console=ttyAMA0 initramfs_async=1"
	cfg := sandboxFsConfig{fuseMount: "/data", fuseBinds: []string{"/etc/ssl/certs", "/workspace"}}
	out := buildSandboxfsAppend(base, cfg)
	want := "console=ttyAMA0 initramfs_async=1 sandboxfs.mount=/data sandboxfs.bind=/etc/ssl/certs,/workspace"
	if out != want {
		t.Fatalf("append mismatch\nwant: %q\ngot:  %q", want, out)
	}
}
