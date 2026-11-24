package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"talisman/gitrepo"
	"talisman/utility"

	"github.com/sirupsen/logrus"
)

type blobDetails struct {
	hash, filePath string
}

// Keep the provenance types available from the scanner package as well; the
// scanner is where the chain is assembled.
type BlobProvenance = gitrepo.BlobProvenance
type PathProvenance = gitrepo.PathProvenance
type ScanStatus = gitrepo.ScanStatus
type Provenance = gitrepo.BlobProvenance

// BlobsInCommits is a map of blob and list of the commits the blob is present
// in.  It also retains the reverse view of the same data (the paths and
// commits associated with a blob) so the result remains usable as a provenance
// chain even when one blob is reached through several paths or commits.
type BlobsInCommits struct {
	commits       map[blobDetails][]string
	pathsByBlob   map[string][]string
	commitsByBlob map[string][]string
	status        gitrepo.ScanStatus
}

type commitScanResult struct {
	index   int
	commit  string
	entries []blobDetails
	err     error
}

// GetAdditions will get all the additions for entire git history.
func GetAdditions(ignoreHistory bool, br gitrepo.BatchReader) []gitrepo.Addition {
	additions, _, _ := GetAdditionsWithStatus(ignoreHistory, br)
	return additions
}

// GetAdditionsWithStatus returns the additions together with the provenance of
// every blob and the status of the scan.  The status is populated even when an
// individual commit or object cannot be inspected; the additions that could be
// read are still returned so a partial report is possible.
func GetAdditionsWithStatus(ignoreHistory bool, br gitrepo.BatchReader) ([]gitrepo.Addition, gitrepo.ScanStatus, []gitrepo.BlobProvenance) {
	blobsInCommits := getBlobsInCommit(ignoreHistory)
	status := blobsInCommits.status

	if len(blobsInCommits.commits) == 0 {
		if status.Error == "" {
			status.Completed = true
		}
		return []gitrepo.Addition{}, status, blobsInCommits.buildProvenance(nil)
	}

	err := br.Start()
	if err != nil {
		status.Completed = false
		status.FailedObject = "git cat-file"
		status.FailedObjectType = "reader"
		status.Error = appendScanError(status.Error, fmt.Sprintf("error creating file reader: %v", err))
		logrus.Errorf("%s", status.Error)
		blobsInCommits.status = status
		return []gitrepo.Addition{}, status, blobsInCommits.buildProvenance(nil)
	}
	defer func() {
		err = br.Shutdown()
		if err != nil {
			logrus.Errorf("error shutting down file reader %v", err)
		}
	}()

	// Read every distinct object once, even when the same blob is reachable
	// through several paths.  This keeps the blob -> path -> commit metadata
	// consistent and avoids doing duplicate work.
	objectHashes := blobsInCommits.objectHashes()
	contents := make(map[string][]byte, len(objectHashes))
	blobErrors := make(map[string]string)
	for _, objectHash := range objectHashes {
		data, readErr := br.Read(objectHash)
		if readErr != nil {
			blobErrors[objectHash] = fmt.Sprintf("error reading blob %s: %v", objectHash, readErr)
			status.Completed = false
			if status.FailedObject == "" {
				status.FailedObject = objectHash
				status.FailedObjectType = "blob"
			}
			status.Error = appendScanError(status.Error, blobErrors[objectHash])
			logrus.Errorf("%s", blobErrors[objectHash])
			continue
		}
		contents[objectHash] = data
	}

	blobs := blobsInCommits.sortedBlobs()
	additions := make([]gitrepo.Addition, 0, len(blobs))
	for _, blob := range blobs {
		data, ok := contents[blob.hash]
		if !ok {
			// The blob could not be read; its provenance records the error
			// below but there is no content to hand to a detector.
			continue
		}
		commits := blobsInCommits.commitsForBlob(blob.hash)
		newAddition := gitrepo.NewScannerAddition(blob.filePath, commits, data, blob.hash)
		additions = append(additions, newAddition)
	}

	if status.Completed {
		status.Completed = len(blobErrors) == 0
	}
	// Keep the tree-walk status on blobsInCommits: an individual blob read
	// failure is recorded per blob, while a failed tree walk makes all
	// provenance incomplete because the set of objects is not known.
	return additions, status, blobsInCommits.buildProvenance(blobErrors)
}

func getBlobsInCommit(ignoreHistory bool) BlobsInCommits {
	progressBar := utility.GetProgressBar(os.Stdout, "Talisman Fetch Blobs")
	blobsInCommits := newBlobsInCommit()
	commits, err := getAllCommitsWithError(ignoreHistory)
	if err != nil {
		blobsInCommits.status.FailedObject = "git log"
		blobsInCommits.status.FailedObjectType = "command"
		blobsInCommits.status.Error = appendScanError(blobsInCommits.status.Error, err.Error())
		return blobsInCommits
	}
	blobsInCommits.status.TotalCommits = len(commits)
	blobsInCommits.status.CommitOrder = append([]string(nil), commits...)
	progressBar.Start(len(commits))

	if len(commits) == 0 {
		progressBar.Finish()
		blobsInCommits.status.Completed = true
		return blobsInCommits
	}

	result := make(chan commitScanResult, len(commits))
	for index, commit := range commits {
		go func(index int, commit string) {
			entries, scanErr := scanCommit(commit)
			result <- commitScanResult{index: index, commit: commit, entries: entries, err: scanErr}
		}(index, commit)
	}

	// Merge in git-log order instead of goroutine completion order.  This
	// makes commit lists stable across runs while still allowing the tree
	// walks to happen concurrently.
	results := make([]commitScanResult, len(commits))
	for range commits {
		scanResult := <-result
		results[scanResult.index] = scanResult
	}

	var scanErrors []string
	for _, scanResult := range results {
		progressBar.Increment()
		if scanResult.err != nil {
			message := fmt.Sprintf("error inspecting commit %s: %v", scanResult.commit, scanResult.err)
			scanErrors = append(scanErrors, message)
			if blobsInCommits.status.FailedObject == "" {
				blobsInCommits.status.FailedObject = scanResult.commit
				blobsInCommits.status.FailedObjectType = "commit"
			}
			continue
		}
		for _, entry := range scanResult.entries {
			blobsInCommits.addEntry(entry, scanResult.commit)
		}
		blobsInCommits.status.ScannedCommits++
	}
	progressBar.Finish()

	if len(scanErrors) > 0 {
		blobsInCommits.status.Completed = false
		blobsInCommits.status.Error = appendScanError(blobsInCommits.status.Error, strings.Join(scanErrors, "; "))
	} else {
		blobsInCommits.status.Completed = true
	}
	return blobsInCommits
}

func scanCommit(commit string) ([]blobDetails, error) {
	blobDetailsBytes, err := exec.Command("git", "-c", "core.quotePath=false", "ls-tree", "-r", commit).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(blobDetailsBytes)))
	}
	entries := make([]blobDetails, 0)
	for _, blobEntry := range strings.Split(string(blobDetailsBytes), "\n") {
		if blobEntry == "" {
			continue
		}
		if entry, ok := parseBlobEntry(blobEntry); ok {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func parseBlobEntry(blobEntry string) (blobDetails, bool) {
	// git ls-tree output is "<mode> <type> <object>\t<path>".  Splitting on
	// the first tab preserves spaces in paths.
	tabIndex := strings.IndexByte(blobEntry, '\t')
	if tabIndex < 0 {
		return blobDetails{}, false
	}
	metadata := strings.Fields(blobEntry[:tabIndex])
	if len(metadata) < 3 {
		return blobDetails{}, false
	}
	return blobDetails{hash: metadata[2], filePath: blobEntry[tabIndex+1:]}, true
}

// putBlobsInChannel is kept for callers that used the original channel based
// API.  The scanner itself uses scanCommit so it can retain errors.
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
	if len(blobEntries) == 0 {
		return
	}
	commit := blobEntries[len(blobEntries)-1]
	for _, blobEntry := range blobEntries[:len(blobEntries)-1] {
		if blobEntry == "" {
			continue
		}
		if entry, ok := parseBlobEntry(blobEntry); ok {
			blobsInCommits.addEntry(entry, commit)
		}
	}
}

func getAllCommits(ignoreHistory bool) []string {
	commits, err := getAllCommitsWithError(ignoreHistory)
	if err != nil {
		logrus.Errorf("%v", err)
		return []string{}
	}
	return commits
}

func getAllCommitsWithError(ignoreHistory bool) ([]string, error) {
	args := []string{"log", "--pretty=%H"}
	if ignoreHistory {
		// Preserve the existing --ignoreHistory semantics: inspect only HEAD,
		// never the rest of the history.
		args = append(args, "--max-count=1")
	} else {
		args = append(args, "--all")
	}
	out, err := exec.Command("git", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git %s failed: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	lines := strings.Split(string(out), "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
	}
	return uniqueStrings(lines), nil
}

func newBlobsInCommit() BlobsInCommits {
	return BlobsInCommits{
		commits:       make(map[blobDetails][]string),
		pathsByBlob:   make(map[string][]string),
		commitsByBlob: make(map[string][]string),
	}
}

func (b *BlobsInCommits) addEntry(entry blobDetails, commit string) {
	if b.commits == nil {
		b.commits = make(map[blobDetails][]string)
	}
	if b.pathsByBlob == nil {
		b.pathsByBlob = make(map[string][]string)
	}
	if b.commitsByBlob == nil {
		b.commitsByBlob = make(map[string][]string)
	}
	key := blobDetails{hash: entry.hash, filePath: entry.filePath}
	b.commits[key] = appendUnique(b.commits[key], commit)
	b.pathsByBlob[entry.hash] = appendUnique(b.pathsByBlob[entry.hash], entry.filePath)
	b.commitsByBlob[entry.hash] = appendUnique(b.commitsByBlob[entry.hash], commit)
}

func (b BlobsInCommits) objectHashes() []string {
	hashes := make([]string, 0, len(b.commitsByBlob))
	for hash := range b.commitsByBlob {
		hashes = append(hashes, hash)
	}
	// Fall back to the public (path keyed) view for callers that built a
	// BlobsInCommits without going through addEntry.
	for blob := range b.commits {
		if _, ok := b.commitsByBlob[blob.hash]; !ok {
			hashes = append(hashes, blob.hash)
		}
	}
	hashes = uniqueStrings(hashes)
	sort.Strings(hashes)
	return hashes
}

func (b BlobsInCommits) sortedBlobs() []blobDetails {
	blobs := make([]blobDetails, 0, len(b.commits))
	for blob := range b.commits {
		blobs = append(blobs, blob)
	}
	sort.SliceStable(blobs, func(i, j int) bool {
		if blobs[i].filePath != blobs[j].filePath {
			return blobs[i].filePath < blobs[j].filePath
		}
		return blobs[i].hash < blobs[j].hash
	})
	return blobs
}

func (b BlobsInCommits) commitsForBlob(hash string) []string {
	if commits, ok := b.commitsByBlob[hash]; ok && len(commits) > 0 {
		return append([]string(nil), commits...)
	}
	// Compatibility fallback for a manually constructed BlobsInCommits.
	commits := make([]string, 0)
	for blob, blobCommits := range b.commits {
		if blob.hash == hash {
			commits = append(commits, blobCommits...)
		}
	}
	return uniqueStrings(commits)
}

func (b BlobsInCommits) buildProvenance(blobErrors map[string]string) []gitrepo.BlobProvenance {
	hashes := b.objectHashes()
	sort.Strings(hashes)
	provenance := make([]gitrepo.BlobProvenance, 0, len(hashes))
	for _, hash := range hashes {
		paths := append([]string(nil), b.pathsByBlob[hash]...)
		if len(paths) == 0 {
			for blob := range b.commits {
				if blob.hash == hash {
					paths = append(paths, blob.filePath)
				}
			}
		}
		sort.Strings(paths)
		paths = uniqueStrings(paths)
		commits := b.commitsForBlob(hash)
		pathCommits := make([]gitrepo.PathProvenance, 0, len(paths))
		for _, path := range paths {
			pathCommits = append(pathCommits, gitrepo.PathProvenance{
				Path:    path,
				Commits: append([]string(nil), b.commits[blobDetails{hash: hash, filePath: path}]...),
			})
		}

		complete := b.status.Completed
		errorMessage := ""
		if blobErrors != nil {
			if blobErr, ok := blobErrors[hash]; ok {
				complete = false
				errorMessage = blobErr
			}
		}
		if !complete && errorMessage == "" {
			errorMessage = b.status.Error
		}
		provenance = append(provenance, gitrepo.BlobProvenance{
			BlobHash:    hash,
			Paths:       paths,
			PathCommits: pathCommits,
			Commits:     commits,
			Complete:    complete,
			Error:       errorMessage,
		})
	}
	return provenance
}

func appendScanError(existing, next string) string {
	if existing == "" {
		return next
	}
	if next == "" || strings.Contains(existing, next) {
		return existing
	}
	return existing + "; " + next
}

func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
