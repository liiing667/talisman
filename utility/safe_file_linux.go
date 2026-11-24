//go:build linux

package utility

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openFileWithoutSymlinks walks the path from the filesystem root one component
// at a time using openat(2) with O_NOFOLLOW. Because each lookup is relative to
// an already-open directory descriptor, replacing a parent directory with a
// symbolic link while the walk is in progress cannot redirect the read outside
// the path that was originally traversed.
func openFileWithoutSymlinks(name string) (*os.File, error) {
	absoluteName, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	cleanName := filepath.Clean(absoluteName)

	dirfd, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	components := strings.Split(strings.TrimPrefix(cleanName, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		if component == "" || component == "." {
			continue
		}

		lastComponent := index == len(components)-1
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
		fd, openErr := syscall.Openat(dirfd, component, flags, 0)
		if openErr != nil {
			syscall.Close(dirfd)
			return nil, &os.PathError{Op: "open", Path: name, Err: classifyOpenError(openErr)}
		}

		if !lastComponent {
			var stat syscall.Stat_t
			if statErr := syscall.Fstat(fd, &stat); statErr != nil {
				syscall.Close(fd)
				syscall.Close(dirfd)
				return nil, &os.PathError{Op: "stat", Path: name, Err: statErr}
			}
			if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
				syscall.Close(fd)
				syscall.Close(dirfd)
				return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOTDIR}
			}
		}

		syscall.Close(dirfd)
		dirfd = fd
	}

	return os.NewFile(uintptr(dirfd), cleanName), nil
}

func classifyOpenError(err error) error {
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
		return errPathContainsSymlink
	}
	return err
}
