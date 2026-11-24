package scanner

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"talisman/gitrepo"
	"talisman/utility"

	"github.com/sirupsen/logrus"
)

type blobDetails struct {
	hash, filePath string
}

// BlobsInCommits is a map of blob and list of the commits the blobs is present in.
type BlobsInCommits struct {
	commits map[blobDetails][]string
}

// BlobReadError represents a git blob that could not be read while collecting
// additions from the repository history (for example because the blob exceeds
// the maximum readable size, or the git object is missing or corrupt).
type BlobReadError struct {
	Path    string
	Commits []string
	Err     error
}

// Error returns a human readable description of the blob read failure.
func (e BlobReadError) Error() string {
	return fmt.Sprintf("could not read blob for file %q: %v", e.Path, e.Err)
}

// GetAdditions will get all the additions for entire git history.
// Blobs that cannot be read are not silently treated as empty files; they are
// reported as BlobReadErrors so that a scan with partial failures is never
// mistaken for a successful one.
func GetAdditions(ignoreHistory bool, br gitrepo.BatchReader) ([]gitrepo.Addition, []BlobReadError) {
	blobsInCommits := getBlobsInCommit(ignoreHistory)
	var additions []gitrepo.Addition
	var readErrors []BlobReadError
	err := br.Start()
	if err != nil {
		logrus.Errorf("error creating file reader %v", err)
	}
	defer func() {
		err = br.Shutdown()
		if err != nil {
			logrus.Errorf("error creating file reader %v", err)
		}
	}()

	for blob := range blobsInCommits.commits {
		contents, err := br.Read(blob.hash)
		if err != nil {
			logrus.Errorf("error reading blob %v for file %v: %v", blob.hash, blob.filePath, err)
			readErrors = append(readErrors, BlobReadError{Path: blob.filePath, Commits: blobsInCommits.commits[blob], Err: err})
			continue
		}
		newAddition := gitrepo.NewScannerAddition(blob.filePath, blobsInCommits.commits[blob], contents)
		additions = append(additions, newAddition)
	}

	return additions, readErrors
}

func getBlobsInCommit(ignoreHistory bool) BlobsInCommits {
	progressBar := utility.GetProgressBar(os.Stdout, "Talisman Fetch Blobs")
	commits := getAllCommits(ignoreHistory)
	progressBar.Start(len(commits) - 1)
	blobsInCommits := newBlobsInCommit()
	result := make(chan []string, len(commits))
	for _, commit := range commits {
		go putBlobsInChannel(commit, result)
	}
	for i := 1; i < len(commits); i++ {
		progressBar.Increment()
		getBlobsFromChannel(blobsInCommits, result)
	}
	progressBar.Finish()
	return blobsInCommits
}

func putBlobsInChannel(commit string, result chan []string) {
	if commit != "" {
		blobDetailsBytes, _ := exec.Command("git", "ls-tree", "-r", commit).CombinedOutput()
		blobDetailsList := strings.Split(string(blobDetailsBytes), "\n")
		blobDetailsList = append(blobDetailsList, commit)
		result <- blobDetailsList
	}
}

func getBlobsFromChannel(blobsInCommits BlobsInCommits, result chan []string) {
	blobEntries := <-result
	commit := blobEntries[len(blobEntries)-1]
	for _, blobEntry := range blobEntries[:len(blobEntries)-1] {
		if blobEntry != "" {
			blobHashAndName := strings.Split(strings.Split(blobEntry, " ")[2], "\t")
			blob := blobDetails{hash: blobHashAndName[0], filePath: blobHashAndName[1]}
			blobsInCommits.commits[blob] = append(blobsInCommits.commits[blob], commit)
		}
	}
}

func getAllCommits(ignoreHistory bool) []string {
	commitRange := "--all"
	if ignoreHistory {
		commitRange = "--max-count=1"
	}
	out, err := exec.Command("git", "log", commitRange, "--pretty=%H").CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}
	return strings.Split(string(out), "\n")
}

func newBlobsInCommit() BlobsInCommits {
	commits := make(map[blobDetails][]string)
	return BlobsInCommits{commits: commits}
}
