package utility

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

func TestShouldReadNormalFileCorrectly(t *testing.T) {
	tempFile, _ := ioutil.TempFile(os.TempDir(), "somefile")
	dataToBeWrittenInFile := []byte{0, 1, 2, 3}
	tempFile.Write(dataToBeWrittenInFile)
	tempFile.Close()

	readDataFromFileUsingIoutilDotReadFile, _ := ioutil.ReadFile(tempFile.Name())
	readDataFromFileUsingSafeFileRead, _ := SafeReadFile(tempFile.Name())
	os.Remove(tempFile.Name())

	assert.Equal(t, readDataFromFileUsingIoutilDotReadFile, dataToBeWrittenInFile)
	assert.Equal(t, readDataFromFileUsingSafeFileRead, dataToBeWrittenInFile)
}

func TestShouldNotReadSymbolicLinkTargetFile(t *testing.T) {
	tempFile, _ := ioutil.TempFile(os.TempDir(), "somefile")
	dataToBeWrittenInFile := []byte{0, 1, 2, 3}
	tempFile.Write(dataToBeWrittenInFile)
	tempFile.Close()
	symlinkFileName := tempFile.Name() + "symlink"
	os.Symlink(tempFile.Name(), symlinkFileName)

	readDataFromSymlinkUsingIoutilDotReadFile, _ := ioutil.ReadFile(symlinkFileName)
	readDataFromSymlinkUsingSafeFileRead, _ := SafeReadFile(symlinkFileName)
	os.Remove(symlinkFileName)
	os.Remove(tempFile.Name())

	assert.Equal(t, readDataFromSymlinkUsingIoutilDotReadFile, dataToBeWrittenInFile)
	assert.Equal(t, readDataFromSymlinkUsingSafeFileRead, []byte{})
}

func TestShouldNotReadFileThroughSymbolicLinkParentDirectory(t *testing.T) {
	outsideDir, _ := ioutil.TempDir("", "outside")
	defer os.RemoveAll(outsideDir)
	dataToBeWrittenInFile := []byte("outside repository")
	ioutil.WriteFile(filepath.Join(outsideDir, "secret"), dataToBeWrittenInFile, 0600)

	repoDir, _ := ioutil.TempDir("", "repo")
	defer os.RemoveAll(repoDir)
	parentLink := filepath.Join(repoDir, "linked")
	if err := os.Symlink(outsideDir, parentLink); err != nil {
		t.Skipf("symbolic links are not available: %v", err)
	}

	readData, err := SafeReadFile(filepath.Join(parentLink, "secret"))

	assert.NoError(t, err)
	assert.Equal(t, []byte{}, readData)
}

func TestShouldNotReadExternalContentWhenPathIsReplacedDuringRead(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the openat-based parent traversal is only available on Linux")
	}

	outsideDir, _ := ioutil.TempDir("", "outside")
	defer os.RemoveAll(outsideDir)
	externalContent := []byte("external content must never be read")
	externalFile := filepath.Join(outsideDir, "secret")
	ioutil.WriteFile(externalFile, externalContent, 0600)

	repoDir, _ := ioutil.TempDir("", "repo")
	defer os.RemoveAll(repoDir)
	target := filepath.Join(repoDir, "target")
	internalContent := []byte("internal content")
	ioutil.WriteFile(target, internalContent, 0600)

	var stop atomic.Bool
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for index := 0; !stop.Load(); index++ {
			replacement := filepath.Join(repoDir, "replacement")
			if index%2 == 0 {
				os.Symlink(externalFile, replacement)
			} else {
				ioutil.WriteFile(replacement, internalContent, 0600)
			}
			os.Rename(replacement, target)
		}
	}()

	for index := 0; index < 2000; index++ {
		readData, err := SafeReadFile(target)
		if err == nil {
			assert.NotEqual(t, externalContent, readData, "external content must never be read")
		}
	}
	stop.Store(true)
	waitGroup.Wait()
}
