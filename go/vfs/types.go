package vfs

import (
	"os"
	"time"
)

const (
	// Linux-style file type bits (matching what Node's fs.Stats.mode exposes)
	S_IFREG = 0o100000
	S_IFDIR = 0o040000
	S_IFLNK = 0o120000
)

// Stats is a lightweight, portable subset of POSIX stat fields.
//
// Mode includes the file type bits (S_IF*) and permission bits.
type Stats struct {
	Mode    uint32
	Nlink   uint32
	UID     uint32
	GID     uint32
	Size    int64
	AtimeMs int64
	MtimeMs int64
	CtimeMs int64
}

func (s Stats) IsDirectory() bool    { return (s.Mode & S_IFDIR) == S_IFDIR }
func (s Stats) IsFile() bool         { return (s.Mode & S_IFREG) == S_IFREG }
func (s Stats) IsSymbolicLink() bool { return (s.Mode & S_IFLNK) == S_IFLNK }

func nowMs() int64 {
	return time.Now().UnixMilli()
}

// Dirent is a directory entry with type information.
type Dirent struct {
	Name string
	Type DirentType
}

type DirentType int

const (
	DirentFile DirentType = iota
	DirentDir
	DirentSymlink
)

func (d Dirent) IsFile() bool         { return d.Type == DirentFile }
func (d Dirent) IsDirectory() bool    { return d.Type == DirentDir }
func (d Dirent) IsSymbolicLink() bool { return d.Type == DirentSymlink }

func fileModeToStatMode(mode os.FileMode) uint32 {
	perm := uint32(mode.Perm())
	if mode&os.ModeSymlink != 0 {
		return S_IFLNK | perm
	}
	if mode.IsDir() {
		return S_IFDIR | perm
	}
	return S_IFREG | perm
}
