package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SandboxState is the lifecycle state of a QEMU sandbox VM.
type SandboxState string

const (
	SandboxStarting SandboxState = "starting"
	SandboxRunning  SandboxState = "running"
	SandboxStopped  SandboxState = "stopped"
)

// SandboxConfig configures QEMU invocation for a sandbox VM.
type SandboxConfig struct {
	/** qemu binary path */
	QemuPath string
	/** kernel image path */
	KernelPath string
	/** initrd/initramfs image path */
	InitrdPath string
	/** optional rootfs image path */
	RootfsPath string
	/** vm memory size (qemu syntax, e.g. "1G") */
	Memory string
	/** vm cpu count */
	Cpus int
	/** virtio-serial control socket path */
	VirtioSocketPath string
	/** virtiofs/vfs socket path */
	VirtioFsSocketPath string
	/** virtio-serial ssh socket path */
	VirtioSshSocketPath string
	/** kernel cmdline append string */
	Append string
	/** qemu machine type */
	MachineType string
	/** qemu acceleration backend (e.g. kvm, hvf, tcg) */
	Accel string
	/** qemu cpu model */
	CPU string
	/** guest console mode */
	Console string // "stdio" | "none"
	/** qemu net socket path */
	NetSocketPath string
	/** guest mac address */
	NetMac string
	/** whether to restart the vm automatically on exit */
	AutoRestart bool
}

// SandboxExit is emitted when the QEMU process exits.
type SandboxExit struct {
	Code   int
	Signal syscall.Signal
	Err    error
}

// SandboxController manages the QEMU process lifecycle.
//
// It is a Go equivalent of host/src/sandbox-controller.ts.
type SandboxController struct {
	mu sync.Mutex

	config SandboxConfig

	cmd    *exec.Cmd
	doneCh chan struct{}
	state  SandboxState

	restartTimer *time.Timer
	manualStop   bool

	// Optional callbacks.
	OnLog   func(line string)
	OnState func(state SandboxState)
	OnExit  func(exit SandboxExit)
}

func NewSandboxController(config SandboxConfig) *SandboxController {
	if config.Memory == "" {
		config.Memory = "1G"
	}
	if config.Cpus <= 0 {
		config.Cpus = 2
	}
	return &SandboxController{config: config, state: SandboxStopped}
}

func (c *SandboxController) SetAppend(append string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.Append = append
}

func (c *SandboxController) State() SandboxState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *SandboxController) setStateLocked(state SandboxState) {
	if c.state == state {
		return
	}
	c.state = state
	onState := c.OnState
	// Call without holding lock to avoid callback re-entrancy issues.
	go func() {
		if onState != nil {
			onState(state)
		}
	}()
}

func (c *SandboxController) Start() error {
	c.mu.Lock()
	if c.cmd != nil {
		c.mu.Unlock()
		return nil
	}
	c.manualStop = false
	c.setStateLocked(SandboxStarting)

	args, err := BuildQemuArgs(c.config)
	if err != nil {
		c.setStateLocked(SandboxStopped)
		c.mu.Unlock()
		return err
	}

	cmd := exec.Command(c.config.QemuPath, args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	cmd.Stdin = nil
	c.cmd = cmd
	c.doneCh = make(chan struct{})
	doneCh := c.doneCh
	c.mu.Unlock()

	if err := cmd.Start(); err != nil {
		c.mu.Lock()
		c.cmd = nil
		close(doneCh)
		c.doneCh = nil
		c.setStateLocked(SandboxStopped)
		c.mu.Unlock()
		return err
	}

	c.mu.Lock()
	c.setStateLocked(SandboxRunning)
	c.mu.Unlock()

	if stdout != nil {
		go c.streamLogs(stdout)
	}
	if stderr != nil {
		go c.streamLogs(stderr)
	}

	go c.waitLoop(cmd, doneCh)

	return nil
}

func (c *SandboxController) streamLogs(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		onLog := func() {}
		c.mu.Lock()
		if c.OnLog != nil {
			onLog = func() { c.OnLog(line) }
		}
		c.mu.Unlock()
		onLog()
	}
}

func (c *SandboxController) waitLoop(cmd *exec.Cmd, doneCh chan struct{}) {
	err := cmd.Wait()

	exit := SandboxExit{Code: 0, Signal: 0, Err: err}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exit.Code = ee.ProcessState.ExitCode()
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
				exit.Signal = ws.Signal()
			}
		} else {
			exit.Code = -1
		}
	} else {
		if cmd.ProcessState != nil {
			exit.Code = cmd.ProcessState.ExitCode()
		}
	}

	c.mu.Lock()
	if c.cmd == cmd {
		c.cmd = nil
	}
	if c.doneCh == doneCh {
		c.doneCh = nil
	}
	close(doneCh)
	manual := c.manualStop
	autoRestart := c.config.AutoRestart
	if !manual && autoRestart {
		c.scheduleRestartLocked()
	}
	c.setStateLocked(SandboxStopped)
	onExit := c.OnExit
	c.mu.Unlock()

	if onExit != nil {
		onExit(exit)
	}
}

func (c *SandboxController) scheduleRestartLocked() {
	if c.restartTimer != nil {
		return
	}
	c.restartTimer = time.AfterFunc(1*time.Second, func() {
		c.mu.Lock()
		c.restartTimer = nil
		c.mu.Unlock()
		_ = c.Start()
	})
}

func (c *SandboxController) Close() error {
	c.mu.Lock()
	cmd := c.cmd
	doneCh := c.doneCh
	c.cmd = nil
	c.doneCh = nil
	c.manualStop = true
	if c.restartTimer != nil {
		c.restartTimer.Stop()
		c.restartTimer = nil
	}
	c.mu.Unlock()

	if cmd == nil {
		return nil
	}

	// Attempt graceful shutdown.
	_ = cmd.Process.Signal(syscall.SIGTERM)

	if doneCh != nil {
		select {
		case <-doneCh:
			// exited
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-doneCh
		}
	}

	c.mu.Lock()
	c.setStateLocked(SandboxStopped)
	c.mu.Unlock()
	return nil
}

func (c *SandboxController) Restart() error {
	if err := c.Close(); err != nil {
		return err
	}
	return c.Start()
}

// BuildQemuArgs builds QEMU arguments for the given config.
//
// This is a Go port of buildQemuArgs() in host/src/sandbox-controller.ts.
func BuildQemuArgs(config SandboxConfig) ([]string, error) {
	if config.QemuPath == "" {
		return nil, errors.New("qemuPath is required")
	}
	if config.KernelPath == "" {
		return nil, errors.New("kernelPath is required")
	}
	if config.InitrdPath == "" {
		return nil, errors.New("initrdPath is required")
	}
	if config.VirtioSocketPath == "" || config.VirtioFsSocketPath == "" || config.VirtioSshSocketPath == "" {
		return nil, errors.New("virtio socket paths are required")
	}

	memory := config.Memory
	if memory == "" {
		memory = "1G"
	}
	cpus := config.Cpus
	if cpus <= 0 {
		cpus = 2
	}

	args := []string{
		"-nodefaults",
		"-no-reboot",
		"-m",
		memory,
		"-smp",
		fmt.Sprintf("%d", cpus),
		"-kernel",
		config.KernelPath,
		"-initrd",
		config.InitrdPath,
		"-append",
		config.Append,
		"-nographic",
	}

	targetArch := detectTargetArch(config.QemuPath)
	machineType := config.MachineType
	if machineType == "" {
		machineType = selectMachineType(targetArch)
	}

	if config.RootfsPath != "" {
		args = append(args,
			"-drive",
			fmt.Sprintf("file=%s,format=raw,if=none,id=drive0,snapshot=on", config.RootfsPath),
		)
		blkDevice := "virtio-blk-pci"
		if machineType == "microvm" {
			blkDevice = "virtio-blk-device"
		}
		args = append(args, "-device", fmt.Sprintf("%s,drive=drive0", blkDevice))
	}

	if machineType == "microvm" {
		args = append(args, "-machine", "microvm,isa-serial=on,auto-kernel-cmdline=on")
	} else {
		args = append(args, "-machine", machineType)
	}

	accel := config.Accel
	if accel == "" {
		accel = selectAccel(targetArch)
	}
	if accel != "" {
		args = append(args, "-accel", accel)
	}

	cpu := config.CPU
	if cpu == "" {
		cpu = selectCPU(targetArch)
	}
	if cpu != "" {
		args = append(args, "-cpu", cpu)
	}

	if config.Console == "none" {
		args = append(args, "-serial", "null")
	} else {
		args = append(args, "-serial", "stdio")
	}

	useMmio := machineType == "microvm"
	rngDev := "virtio-rng-pci"
	serialDev := "virtio-serial-pci"
	netDev := "virtio-net-pci"
	if useMmio {
		rngDev = "virtio-rng-device"
		serialDev = "virtio-serial-device"
		netDev = "virtio-net-device"
	}

	args = append(args,
		"-object",
		"rng-random,filename=/dev/urandom,id=rng0",
		"-device",
		fmt.Sprintf("%s,rng=rng0", rngDev),
		"-chardev",
		fmt.Sprintf("socket,id=virtiocon0,path=%s,server=off", config.VirtioSocketPath),
		"-chardev",
		fmt.Sprintf("socket,id=virtiofs0,path=%s,server=off", config.VirtioFsSocketPath),
		"-chardev",
		fmt.Sprintf("socket,id=virtiossh0,path=%s,server=off", config.VirtioSshSocketPath),
		"-device",
		fmt.Sprintf("%s,id=virtio-serial0", serialDev),
		"-device",
		"virtserialport,chardev=virtiocon0,name=virtio-port,bus=virtio-serial0.0",
		"-device",
		"virtserialport,chardev=virtiofs0,name=virtio-fs,bus=virtio-serial0.0",
		"-device",
		"virtserialport,chardev=virtiossh0,name=virtio-ssh,bus=virtio-serial0.0",
	)

	if config.NetSocketPath != "" {
		args = append(args,
			"-netdev",
			fmt.Sprintf("stream,id=net0,server=off,addr.type=unix,addr.path=%s", config.NetSocketPath),
		)
		mac := config.NetMac
		if mac == "" {
			mac = "02:00:00:00:00:01"
		}
		args = append(args, "-device", fmt.Sprintf("%s,netdev=net0,mac=%s", netDev, mac))
	}

	return args, nil
}

func detectTargetArch(qemuPath string) string {
	p := strings.ToLower(qemuPath)
	if strings.Contains(p, "aarch64") || strings.Contains(p, "arm64") {
		return "arm64"
	}
	if strings.Contains(p, "x86_64") || strings.Contains(p, "x64") {
		return "x64"
	}
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "x64"
}

func selectMachineType(targetArch string) string {
	if runtime.GOOS == "linux" && targetArch == "x64" {
		return "microvm"
	}
	if targetArch == "arm64" {
		return "virt"
	}
	return "q35"
}

func hostArch() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "x64"
}

func selectAccel(targetArch string) string {
	// Cross-arch emulation cannot use hardware acceleration.
	if targetArch != hostArch() {
		return "tcg"
	}

	if runtime.GOOS == "linux" {
		if err := accessRW("/dev/kvm"); err == nil {
			return "kvm"
		}
		return "tcg"
	}
	if runtime.GOOS == "darwin" {
		return "hvf"
	}
	return "tcg"
}

func selectCPU(targetArch string) string {
	if targetArch != hostArch() {
		return "max"
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		return "host"
	}
	return "max"
}

func accessRW(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	_ = f.Close()
	return nil
}
