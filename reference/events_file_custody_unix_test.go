//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package reference

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestEventFileCustodyRequiresCurrentEffectiveUser(t *testing.T) {
	current := uint32(os.Geteuid())
	if !eventFileOwnedByCurrentUser(custodyFileInfo{uid: current}) {
		t.Fatal("current effective user was not accepted as file owner")
	}
	foreign := current + 1
	if foreign == current {
		foreign--
	}
	if eventFileOwnedByCurrentUser(custodyFileInfo{uid: foreign}) {
		t.Fatal("foreign file owner was accepted")
	}
}

type custodyFileInfo struct {
	uid uint32
}

func (info custodyFileInfo) Name() string       { return "custody" }
func (info custodyFileInfo) Size() int64        { return 0 }
func (info custodyFileInfo) Mode() fs.FileMode  { return 0o600 }
func (info custodyFileInfo) ModTime() time.Time { return time.Time{} }
func (info custodyFileInfo) IsDir() bool        { return false }
func (info custodyFileInfo) Sys() any {
	return &syscall.Stat_t{Uid: info.uid, Nlink: 1}
}
