//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package snapshotfile

import "os"

type fileLock struct{}

func acquireFileLock(string) (*fileLock, error) { return nil, ErrConfig }

func (*fileLock) Close() error { return nil }

func hasSingleLink(os.FileInfo) bool { return true }

func ownedByCurrentUser(os.FileInfo) bool { return false }
