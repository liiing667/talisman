//go:build !linux

package utility

import (
	"os"
	"path/filepath"
	"strings"
)

// openFileWithoutSymlinks is the portable fallback for platforms that do not
// provide the openat-based walk. Every path component is checked with Lstat
// before the file is opened.
func openFileWithoutSymlinks(name string) (*os.File, error) {
	absoluteName, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	cleanName := filepath.Clean(absoluteName)

	volumeName := filepath.VolumeName(cleanName)
	currentPath := volumeName + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(cleanName, volumeName), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		currentPath = filepath.Join(currentPath, component)
		fileInfo, err := os.Lstat(currentPath)
		if err != nil {
			return nil, err
		}
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			return nil, errPathContainsSymlink
		}
	}

	return os.Open(cleanName)
}
