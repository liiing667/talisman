package scanner

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"talisman/git_testing"
	"talisman/gitrepo"

	logr "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func init() {
	logr.SetOutput(ioutil.Discard)
	git_testing.Logger = logr.WithField("Environment", "Debug")
}

func Test_getBlobsFromChannel(t *testing.T) {
	ch := make(chan []string)
	go func() {
		ch <- []string{
			"100644 blob 351324aa7b3c66043e484c2f2c7b7f1842152f35	.gitignore",
			"100644 blob 8715df9907604c8ee8fc5e377821817f84f014fa	.pre-commit-hooks.yaml",
			"commitSha",
		}
	}()
	blobsInCommits := BlobsInCommits{commits: map[blobDetails][]string{}}
	getBlobsFromChannel(blobsInCommits, ch)

	commits := blobsInCommits.commits
	assert.Len(t, commits, 2)
	assert.Equal(t, []string{"commitSha"}, commits[blobDetails{"351324aa7b3c66043e484c2f2c7b7f1842152f35", ".gitignore"}])
	assert.Equal(t, []string{"commitSha"}, commits[blobDetails{"8715df9907604c8ee8fc5e377821817f84f014fa", ".pre-commit-hooks.yaml"}])
}

type stubBatchReader struct {
	contentsByHash map[string][]byte
	errorsByHash   map[string]error
}

func (s *stubBatchReader) Start() error    { return nil }
func (s *stubBatchReader) Shutdown() error { return nil }
func (s *stubBatchReader) Read(hash string) ([]byte, error) {
	if err, ok := s.errorsByHash[hash]; ok {
		return nil, err
	}
	return s.contentsByHash[hash], nil
}

func blobHashOf(t *testing.T, git *git_testing.GitTesting, fileName string) string {
	details := git.GetBlobDetails(fileName) // "<hash> <fileName>"
	parts := strings.Split(details, " ")
	if len(parts) != 2 || parts[0] == "" {
		t.Fatalf("could not find blob hash for %s", fileName)
	}
	return parts[0]
}

func inRepoDir(git *git_testing.GitTesting, operation func()) {
	wd, _ := os.Getwd()
	os.Chdir(git.Root())
	defer os.Chdir(wd)
	operation()
}

func TestGetAdditionsReturnsReadErrorsInsteadOfTreatingFailuresAsEmptyFiles(t *testing.T) {
	git_testing.DoInTempGitRepo(func(git *git_testing.GitTesting) {
		git.SetupBaselineFiles("baseline.txt")
		git.CreateFileWithContents("good.txt", "good contents")
		git.CreateFileWithContents("too-big.txt", "contents that will not be read")
		git.AddAndcommit("*", "added good and too-big files")

		inRepoDir(git, func() {
			goodHash := blobHashOf(t, git, "good.txt")
			tooBigHash := blobHashOf(t, git, "too-big.txt")
			reader := &stubBatchReader{
				contentsByHash: map[string][]byte{goodHash: []byte("good contents")},
				errorsByHash: map[string]error{
					tooBigHash: fmt.Errorf("%w: %s is 2048 bytes, larger than the maximum of 1024 bytes", gitrepo.ErrBlobTooLarge, tooBigHash),
				},
			}

			additions, readErrors := GetAdditions(true, reader)

			if assert.Len(t, readErrors, 1, "expected the unreadable blob to be reported as a read error") {
				assert.Equal(t, "too-big.txt", readErrors[0].Path)
				assert.NotEmpty(t, readErrors[0].Commits)
				assert.True(t, errors.Is(readErrors[0].Err, gitrepo.ErrBlobTooLarge))
			}
			for _, addition := range additions {
				assert.NotEqual(t, "too-big.txt", string(addition.Path), "failed reads must not be returned as (empty) additions")
				if string(addition.Path) == "good.txt" {
					assert.Equal(t, "good contents", string(addition.Data))
				}
			}
		})
	})
}

func TestGetAdditionsReturnsAllAdditionsAndNoErrorsWhenAllReadsSucceed(t *testing.T) {
	git_testing.DoInTempGitRepo(func(git *git_testing.GitTesting) {
		git.SetupBaselineFiles("baseline.txt")
		git.CreateFileWithContents("medium.txt", "medium contents")
		git.AddAndcommit("*", "added medium file")

		inRepoDir(git, func() {
			reader := &stubBatchReader{
				contentsByHash: map[string][]byte{
					blobHashOf(t, git, "medium.txt"): []byte("medium contents"),
				},
			}

			additions, readErrors := GetAdditions(true, reader)

			assert.Empty(t, readErrors, "no read errors expected when all blobs are readable")
			var paths []string
			for _, addition := range additions {
				paths = append(paths, string(addition.Path))
			}
			assert.Contains(t, paths, "medium.txt")
			assert.Contains(t, paths, "baseline.txt")
		})
	})
}
