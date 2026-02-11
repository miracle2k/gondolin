package sandbox

import (
	"strings"
	"testing"
)

func TestBuildQemuArgsIncludesVirtioPorts(t *testing.T) {
	cfg := SandboxConfig{
		QemuPath:            "qemu-system-aarch64",
		KernelPath:          "/kernel",
		InitrdPath:          "/initrd",
		RootfsPath:          "/rootfs",
		Memory:              "1G",
		Cpus:                2,
		VirtioSocketPath:    "/tmp/virtio.sock",
		VirtioFsSocketPath:  "/tmp/virtiofs.sock",
		VirtioSshSocketPath: "/tmp/virtiossh.sock",
		Append:              "console=ttyAMA0 initramfs_async=1",
		NetSocketPath:       "/tmp/net.sock",
		NetMac:              "02:00:00:00:00:01",
	}

	args, err := BuildQemuArgs(cfg)
	if err != nil {
		t.Fatalf("BuildQemuArgs: %v", err)
	}
	joined := strings.Join(args, " ")

	want := []string{
		"socket,id=virtiocon0,path=/tmp/virtio.sock,server=off",
		"socket,id=virtiofs0,path=/tmp/virtiofs.sock,server=off",
		"socket,id=virtiossh0,path=/tmp/virtiossh.sock,server=off",
		"virtserialport,chardev=virtiocon0,name=virtio-port",
		"virtserialport,chardev=virtiofs0,name=virtio-fs",
		"virtserialport,chardev=virtiossh0,name=virtio-ssh",
		"stream,id=net0,server=off,addr.type=unix,addr.path=/tmp/net.sock",
	}
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Fatalf("expected args to include %q\nargs=%s", w, joined)
		}
	}
}
