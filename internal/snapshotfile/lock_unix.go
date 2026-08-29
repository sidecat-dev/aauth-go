//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package snapshotfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type fileLock struct {
	file *os.File
}

func acquireFileLock(directory string) (*fileLock, error) {
	path := filepath.Join(directory, lockName)
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o600 || !hasSingleLink(info) || !ownedByCurrentUser(info) {
			return nil, ErrUnsafe
		}
	case errors.Is(err, os.ErrNotExist):
		created, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr == nil {
			if closeErr := created.Close(); closeErr != nil {
				return nil, fmt.Errorf("snapshotfile: close new lock: %w", closeErr)
			}
		} else if !errors.Is(createErr, os.ErrExist) {
			return nil, fmt.Errorf("snapshotfile: create lock: %w", createErr)
		}
	default:
		return nil, fmt.Errorf("snapshotfile: inspect lock: %w", err)
	}
	openedFile, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("snapshotfile: open lock: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = openedFile.Close()
		}
	}()
	opened, err := openedFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("snapshotfile: inspect opened lock: %w", err)
	}
	linked, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, linked) || !opened.Mode().IsRegular() ||
		opened.Mode().Perm() != 0o600 || !hasSingleLink(opened) || !ownedByCurrentUser(opened) {
		return nil, ErrUnsafe
	}
	if err := syscall.Flock(int(openedFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("snapshotfile: acquire writer lock: %w", err)
	}
	failed = false
	return &fileLock{file: openedFile}, nil
}

func (lock *fileLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return errors.Join(unlockErr, file.Close())
}

func hasSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
