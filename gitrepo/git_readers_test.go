package gitrepo

import (
	"errors"
	"strings"
	"testing"

	"talisman/git_testing"

	"github.com/stretchr/testify/assert"
)

func blobHashForFile(git *git_testing.GitTesting, fileName string) string {
	details := git.GetBlobDetails(fileName) // "<hash> <fileName>"
	parts := strings.Split(details, " ")
	if len(parts) != 2 || parts[0] == "" {
		panic("could not find blob hash for " + fileName)
	}
	return parts[0]
}

func newObjectHashReaderWithMaxBlobSize(root string, maxBlobSize int) *BatchGitObjectReader {
	bgor := newBatchGitObjectReader(root, maxBlobSize)
	bgor.read = bgor.makeObjectHashReader()
	return bgor
}

func TestBatchReaderReadsRegularFileWithinBudget(t *testing.T) {
	doInRepoWithCommit(func(git *git_testing.GitTesting) {
		git.CreateFileWithContents("medium.txt", "just a regular,\nmedium sized file\nwith a few lines\n")
		git.AddAndcommit("*", "added medium file")

		reader := NewBatchGitObjectHashReader(git.Root())
		assert.NoError(t, reader.Start())
		defer reader.Shutdown()

		contents, err := reader.Read(blobHashForFile(git, "medium.txt"))
		assert.NoError(t, err)
		assert.Equal(t, "just a regular,\nmedium sized file\nwith a few lines\n", string(contents))
	})
}

func TestBatchReaderRejectsOversizedBlobBeforeReadingItIntoMemory(t *testing.T) {
	doInRepoWithCommit(func(git *git_testing.GitTesting) {
		git.CreateFileWithContents("big.txt", strings.Repeat("a", 2048))
		git.CreateFileWithContents("small.txt", "small contents")
		git.AddAndcommit("*", "added big and small files")

		reader := newObjectHashReaderWithMaxBlobSize(git.Root(), 1024)
		assert.NoError(t, reader.Start())
		defer reader.Shutdown()

		contents, err := reader.Read(blobHashForFile(git, "big.txt"))
		assert.Error(t, err, "expected an error when reading a blob larger than the budget")
		assert.True(t, errors.Is(err, ErrBlobTooLarge), "expected error to wrap ErrBlobTooLarge, got: %v", err)
		assert.Empty(t, contents, "oversized blob contents should not be returned")

		//The stream must still be in sync: subsequent reads keep working.
		contents, err = reader.Read(blobHashForFile(git, "small.txt"))
		assert.NoError(t, err)
		assert.Equal(t, "small contents", string(contents))
	})
}

func TestBatchReaderRejectsFileWithMultipleLongLinesExceedingBudget(t *testing.T) {
	doInRepoWithCommit(func(git *git_testing.GitTesting) {
		longLine := strings.Repeat("x", 500)
		git.CreateFileWithContents("long-lines.txt", longLine+"\n"+longLine+"\n"+longLine+"\n")
		git.CreateFileWithContents("single-long-line.txt", longLine+"\n")
		git.AddAndcommit("*", "added files with long lines")

		reader := newObjectHashReaderWithMaxBlobSize(git.Root(), 1024)
		assert.NoError(t, reader.Start())
		defer reader.Shutdown()

		_, err := reader.Read(blobHashForFile(git, "long-lines.txt"))
		assert.True(t, errors.Is(err, ErrBlobTooLarge), "expected ErrBlobTooLarge for multiple long lines, got: %v", err)

		contents, err := reader.Read(blobHashForFile(git, "single-long-line.txt"))
		assert.NoError(t, err, "a file with long lines within budget should still be read")
		assert.Equal(t, longLine+"\n", string(contents))
	})
}

func TestBatchReaderReturnsErrorForMissingGitObject(t *testing.T) {
	doInRepoWithCommit(func(git *git_testing.GitTesting) {
		git.CreateFileWithContents("present.txt", "present contents")
		git.AddAndcommit("*", "added present file")

		reader := NewBatchGitObjectHashReader(git.Root())
		assert.NoError(t, reader.Start())
		defer reader.Shutdown()

		contents, err := reader.Read("0123456789abcdef0123456789abcdef01234567")
		assert.Error(t, err, "expected an error when reading a missing git object")
		assert.Empty(t, contents, "missing objects must not be treated as empty files")

		//The stream must still be in sync: subsequent reads keep working.
		contents, err = reader.Read(blobHashForFile(git, "present.txt"))
		assert.NoError(t, err)
		assert.Equal(t, "present contents", string(contents))
	})
}
