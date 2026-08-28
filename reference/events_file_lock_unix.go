//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package reference

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

type eventFileLock struct {
	file *os.File
}

func acquireEventFileLock(directory string) (*eventFileLock, error) {
	path := filepath.Join(directory, eventFileLockName)
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o600 || !eventFileHasSingleLink(info) || !eventFileOwnedByCurrentUser(info) {
			return nil, ErrEventStoreUnsafe
		}
	case errors.Is(err, os.ErrNotExist):
		created, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr == nil {
			if closeErr := created.Close(); closeErr != nil {
				return nil, closeErr
			}
		} else if !errors.Is(createErr, os.ErrExist) {
			return nil, createErr
		}
	default:
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	linked, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, linked) || !opened.Mode().IsRegular() ||
		opened.Mode().Perm() != 0o600 || !eventFileHasSingleLink(opened) || !eventFileOwnedByCurrentUser(opened) {
		return nil, ErrEventStoreUnsafe
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrEventStoreLocked
		}
		return nil, err
	}
	failed = false
	return &eventFileLock{file: file}, nil
}

func (lock *eventFileLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return errors.Join(unlockErr, file.Close())
}

func eventFileHasSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func eventFileOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
