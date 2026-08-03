//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package reference

import "os"

type eventFileLock struct{}

func acquireEventFileLock(string) (*eventFileLock, error) {
	return nil, ErrEventStoreConfig
}

func (*eventFileLock) Close() error { return nil }

func eventFileHasSingleLink(os.FileInfo) bool { return true }
