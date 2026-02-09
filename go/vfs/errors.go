package vfs

import (
	"fmt"
	"syscall"
)

// ErrnoError is an error with a POSIX errno value.
//
// It is used throughout the VFS and FsRpcService to serialize errors over the wire.
type ErrnoError struct {
	Errno   int
	Syscall string
	Path    string
	Message string
}

func (e *ErrnoError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	code := fmt.Sprintf("ERRNO_%d", e.Errno)
	if e.Errno > 0 {
		code = syscall.Errno(e.Errno).Error()
	}
	if e.Path != "" {
		return fmt.Sprintf("%s: %s '%s'", code, e.Syscall, e.Path)
	}
	return fmt.Sprintf("%s: %s", code, e.Syscall)
}

func CreateErrnoError(errno int, syscallName string, path string) *ErrnoError {
	return &ErrnoError{Errno: errno, Syscall: syscallName, Path: path}
}
