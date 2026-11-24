package utility

import (
	"errors"
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"
)

// errPathContainsSymlink is returned by openFileWithoutSymlinks when any
// component of the requested path is a symbolic link.
var errPathContainsSymlink = errors.New("path contains a symbolic link")

// SafeReadFile reads a file without following symbolic links in any component
// of its path. Reading is performed through a single opened file descriptor:
// the file that is validated is exactly the file whose bytes are returned.
//
// A symbolic link in the path (including a parent directory) is skipped by
// returning an empty slice and a nil error. This retains Talisman's explicit
// symlink-skip behaviour while preventing a path from being swapped for a link
// to a file outside the repository between validation and use.
func SafeReadFile(path string) ([]byte, error) {
	file, err := openFileWithoutSymlinks(path)
	if err != nil {
		if errors.Is(err, errPathContainsSymlink) {
			log.Debug("Symlink was detected! Not following symlink ", path)
			return []byte{}, nil
		}
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !fileInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to read non-regular file %s", path)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return data, nil
}
