package gitrepo

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// FilePath represents the absolute path of an added file
type FilePath string

// FileName represents the base name of an added file
type FileName string

// Addition represents the end state of a file
type Addition struct {
	Path    FilePath
	Name    FileName
	Commits []string
	Data    []byte
}

// GitRepo represents a Git repository located at the absolute path represented by root
type GitRepo struct {
	root string
}

// RepoLocatedAt returns a new GitRepo with it's root located at the location specified by the argument.
// If the argument is not an absolute path, it will be turned into one.
func RepoLocatedAt(path string) GitRepo {
	absoluteRoot, _ := filepath.Abs(path)
	return GitRepo{absoluteRoot}
}

func (repo GitRepo) Root() string {
	return repo.root
}

// GetDiffForStagedFiles gets all the staged files and collects the diff section in each file
func (repo GitRepo) GetDiffForStagedFiles() []Addition {
	stagedContent := repo.executeRepoCommand(
		"git",
		"-c", "core.quotePath=false",
		"diff",
		"--staged",
		"--src-prefix=a/",
		"--dst-prefix=b/",
		"--find-renames",
	)
	content := strings.TrimRight(string(stagedContent), "\n")
	result := make([]Addition, 0)

	if len(content) == 0 {
		return result
	}

	// Standard git diff header pattern
	// ref: https://git-scm.com/docs/diff-format#_generating_patches_with_p
	lines := strings.Split(content, "\n")
	var headerFilename string
	var renamedFilename string
	var plusFilename string
	deleted := false
	inSection := false
	additionContentBuffer := &strings.Builder{}

	flushAddition := func() {
		if !inSection {
			return
		}

		if deleted {
			headerFilename = ""
			renamedFilename = ""
			plusFilename = ""
			deleted = false
			inSection = false
			additionContentBuffer.Reset()
			return
		}

		// Prefer the destination named by the patch itself. This keeps a
		// renamed file tied to the path it has in the staged snapshot, even
		// when the a/ and b/ header paths differ.
		additionFilename := plusFilename
		if additionFilename == "" {
			additionFilename = renamedFilename
		}
		if additionFilename == "" {
			additionFilename = headerFilename
		}

		if additionFilename != "" {
			stagedChanges := repo.extractAdditions(additionContentBuffer.String())
			if stagedChanges != nil {
				result = append(result, NewAddition(additionFilename, stagedChanges))
			}
		}

		headerFilename = ""
		renamedFilename = ""
		plusFilename = ""
		deleted = false
		inSection = false
		additionContentBuffer.Reset()
	}

	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "diff --git ") {
			flushAddition()
			inSection = true
			_, headerFilename = MatchGitDiffLine(line)
			continue
		}

		if !inSection {
			continue
		}

		switch {
		case strings.HasPrefix(line, "deleted file mode "):
			deleted = true
		case strings.HasPrefix(line, "rename to "):
			renamedFilename = parseGitDiffPath(strings.TrimPrefix(line, "rename to "), "")
		case strings.HasPrefix(line, "copy to "):
			renamedFilename = parseGitDiffPath(strings.TrimPrefix(line, "copy to "), "")
		case strings.HasPrefix(line, "+++ "):
			path := parseGitDiffPath(strings.TrimPrefix(line, "+++ "), "b/")
			if path != "" && path != "/dev/null" {
				plusFilename = path
			} else if path == "/dev/null" {
				deleted = true
			}
		}

		additionContentBuffer.WriteString(line)
		additionContentBuffer.WriteRune('\n')
	}

	flushAddition()

	log.WithFields(log.Fields{
		"additions": result,
	}).Debug("Generating staged additions.")

	return result
}

func MatchGitDiffLine(gitDiffString string) (bool, string) {
	const headerPrefix = "diff --git "
	gitDiffString = strings.TrimSuffix(gitDiffString, "\r")
	if !strings.HasPrefix(gitDiffString, headerPrefix) {
		return false, ""
	}

	_, destination, ok := splitGitDiffHeader(strings.TrimPrefix(gitDiffString, headerPrefix))
	if !ok {
		return false, ""
	}
	return true, destination
}

// splitGitDiffHeader splits the "a/<path> b/<path>" portion of a diff header.
// Git does not quote paths containing spaces, so prefer a split that describes
// the same path on both sides (the common modification/deletion case).
func splitGitDiffHeader(header string) (string, string, bool) {
	if strings.HasPrefix(header, `"`) {
		source, remainder, ok := consumeQuotedGitPath(header)
		if !ok {
			return "", "", false
		}
		remainder = strings.TrimPrefix(remainder, " ")
		destination := remainder
		if strings.HasPrefix(remainder, `"`) {
			var destinationOK bool
			destination, _, destinationOK = consumeQuotedGitPath(remainder)
			if !destinationOK {
				return "", "", false
			}
		}
		return strings.TrimPrefix(source, "a/"), strings.TrimPrefix(destination, "b/"), true
	}

	// Only the destination is quoted. Since an unquoted source cannot contain
	// a double quote, the space before the quoted token is the separator.
	if index := strings.Index(header, ` "`); index >= 0 {
		source := header[:index]
		destination, _, ok := consumeQuotedGitPath(header[index+1:])
		if ok && strings.HasPrefix(source, "a/") && strings.HasPrefix(destination, "b/") {
			return strings.TrimPrefix(source, "a/"), strings.TrimPrefix(destination, "b/"), true
		}
	}

	var separators []int
	for offset := 0; offset < len(header); {
		index := strings.Index(header[offset:], " b/")
		if index < 0 {
			break
		}
		separator := offset + index
		separators = append(separators, separator)
		offset = separator + 1
	}

	for _, separator := range separators {
		source := header[:separator]
		destination := header[separator+1:]
		if !strings.HasPrefix(source, "a/") || !strings.HasPrefix(destination, "b/") {
			continue
		}
		if strings.TrimPrefix(source, "a/") == strings.TrimPrefix(destination, "b/") {
			return strings.TrimPrefix(source, "a/"), strings.TrimPrefix(destination, "b/"), true
		}
	}

	// A rename/copy has different paths on each side. Pick the most
	// plausible split; this also copes with spaces in both paths, where a
	// " b/" sequence can legitimately occur inside either name.
	bestSeparator := -1
	bestScore := -1
	for _, separator := range separators {
		source := header[:separator]
		destination := header[separator+1:]
		if !strings.HasPrefix(source, "a/") || !strings.HasPrefix(destination, "b/") {
			continue
		}
		source = strings.TrimPrefix(source, "a/")
		destination = strings.TrimPrefix(destination, "b/")
		score := 0
		if strings.Count(source, "/") == strings.Count(destination, "/") {
			score++
		}
		if path.Ext(source) == path.Ext(destination) {
			score++
		}
		if score >= bestScore {
			bestScore = score
			bestSeparator = separator
		}
	}
	if bestSeparator >= 0 {
		source := strings.TrimPrefix(header[:bestSeparator], "a/")
		destination := strings.TrimPrefix(header[bestSeparator+1:], "b/")
		return source, destination, true
	}

	return "", "", false
}

func consumeQuotedGitPath(value string) (string, string, bool) {
	if len(value) == 0 || value[0] != '"' {
		return "", "", false
	}
	for i := 1; i < len(value); i++ {
		switch value[i] {
		case '\\':
			i++
		case '"':
			unquoted, err := strconv.Unquote(value[:i+1])
			if err != nil {
				return "", "", false
			}
			return unquoted, value[i+1:], true
		}
	}
	return "", "", false
}

func parseGitDiffPath(value, prefix string) string {
	value = strings.TrimSuffix(value, "\r")
	if strings.HasPrefix(value, `"`) {
		if unquoted, _, ok := consumeQuotedGitPath(value); ok {
			value = unquoted
		}
	} else if index := strings.IndexByte(value, '\t'); index >= 0 {
		// Git appends a tab before the (empty) timestamp when the path
		// contains spaces.
		value = value[:index]
	}
	return strings.TrimPrefix(value, prefix)
}

// StagedAdditions returns the files staged for commit in a GitRepo
func (repo GitRepo) StagedAdditions() []Addition {
	files := repo.stagedFiles()
	result := make([]Addition, len(files))
	for i, file := range files {
		data, _ := repo.readRepoFile(file, GIT_STAGED_PREFIX)
		result[i] = NewAddition(file, data)
	}

	log.WithFields(log.Fields{
		"additions": result,
	}).Info("Generating staged additions.")
	return result
}

// AdditionsWithinRange returns the outgoing additions and modifications in a GitRepo that are in the given commit range. This does not include files that were deleted.
func (repo GitRepo) AdditionsWithinRange(oldCommit string, newCommit string) []Addition {
	files := repo.outgoingNonDeletedFiles(oldCommit, newCommit)
	result := make([]Addition, len(files))
	for i, file := range files {
		data, _ := repo.readRepoFile(file, GIT_HEAD_PREFIX)
		result[i] = NewAddition(file, data)
	}
	log.WithFields(log.Fields{
		"oldCommit": oldCommit,
		"newCommit": newCommit,
		"additions": result,
	}).Info("Generating all additions in range.")
	return result
}

// NewAddition returns a new Addition for a file with supplied name and contents
func NewAddition(filePath string, content []byte) Addition {
	return Addition{
		Path: FilePath(filePath),
		Name: FileName(path.Base(filePath)),
		Data: content,
	}
}

// NewScannerAddition returns an new Addition for a file with supplied contents and all of the commits the file is in
func NewScannerAddition(filePath string, commits []string, content []byte) Addition {
	return Addition{
		Path:    FilePath(filePath),
		Name:    FileName(path.Base(filePath)),
		Commits: commits,
		Data:    content,
	}
}

// CheckIfFileExists checks if the file exists on the file system. Does not look into the file contents
// Returns TRUE if file exists
// Returns FALSE if the file is not found
func (repo GitRepo) CheckIfFileExists(fileName string) bool {
	filepath := path.Join(repo.root, fileName)
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return false
	}
	return true
}

// Matches reports whether the addition matches the given pattern.
//
// If the pattern ends in a path separator, then all files inside a directory with that name are matched.
// However, files with that name itself will not be matched.
//
// If a pattern contains the path separator in any other location,
// the match works according to the pattern logic of the default golang glob mechanism.
//
// If there are other special characters in the pattern, the pattern is matched against the base name of the file.
// Thus, the pattern will match files with that pattern anywhere in the repository.
//
// If there are no special characters in the pattern, then it means exact filename is provided as pattern like file.txt.
// Thus, the pattern is matched against the file path so that not all files with the same name in the repo are not returned.
func (a Addition) Matches(pattern string) bool {
	var result bool
	if pattern[len(pattern)-1] == '/' { // If the pattern ends in a path separator, then all files inside a directory with that name are matched. However, files with that name itself will not be matched.
		result = strings.HasPrefix(string(a.Path), pattern)
	} else if strings.ContainsRune(pattern, '/') { // If a pattern contains the path separator in any other location, the match works according to the pattern logic of the default golang glob mechanism
		result, _ = path.Match(pattern, string(a.Path))
	} else if strings.ContainsAny(pattern, "*?[]\\") { // If there are other special characters in the pattern, the pattern is matched against the base name of the file. Thus, the pattern will match files with that pattern anywhere in the repository.
		result = a.NameMatches(pattern)
	} else { // If there are no special characters in the pattern, then it means exact filename is provided as pattern like file.txt. Thus, the pattern is matched against the file path so that not all files with the same name in the repo are not returned.
		result = strings.Compare(string(a.Path), pattern) == 0
	}
	log.WithFields(log.Fields{
		"pattern":  pattern,
		"filePath": a.Path,
		"match":    result,
	}).Debug("Checking addition for match.")
	return result
}

// NameMatches reports whether the basename of the Addition matches the given pattern
func (a Addition) NameMatches(pattern string) bool {
	result, _ := path.Match(pattern, string(a.Name))
	return result
}

// TrackedFilesAsAdditions returns all of the tracked files in a GitRepo as Additions
func (repo GitRepo) TrackedFilesAsAdditions() []Addition {
	trackedFilePaths := repo.trackedFilePaths()
	var additions []Addition
	for _, path := range trackedFilePaths {
		additions = append(additions, NewAddition(path, make([]byte, 0)))
	}
	return additions
}

// IndexFilesAsAdditions returns every path in the staged snapshot (the index)
// as an Addition. Unlike TrackedFilesAsAdditions, this reflects renames and
// other staged changes instead of the paths from the last commit.
func (repo GitRepo) IndexFilesAsAdditions() []Addition {
	byteArray := repo.executeRepoCommand("git", "ls-files", "-z")
	var additions []Addition
	for _, path := range strings.Split(string(byteArray), "\x00") {
		if path != "" {
			additions = append(additions, NewAddition(path, make([]byte, 0)))
		}
	}
	return additions
}

// StagedSnapshotFilesAsAdditions returns the path set of the current staged
// snapshot while retaining the historical ordering of tracked files followed
// by newly staged files. Paths that disappeared from the index (for example
// because they were renamed or deleted) are not carried over from HEAD.
func (repo GitRepo) StagedSnapshotFilesAsAdditions() []Addition {
	indexAdditions := repo.IndexFilesAsAdditions()
	indexPaths := make(map[string]bool)
	for _, addition := range indexAdditions {
		indexPaths[string(addition.Path)] = true
	}

	seen := make(map[string]bool)
	var result []Addition
	for _, addition := range repo.TrackedFilesAsAdditions() {
		path := string(addition.Path)
		if indexPaths[path] && !seen[path] {
			result = append(result, addition)
			seen[path] = true
		}
	}
	for _, addition := range repo.StagedAdditions() {
		path := string(addition.Path)
		if !seen[path] {
			result = append(result, addition)
			seen[path] = true
		}
	}
	// Guard against a source list that is unavailable (for example a
	// detached HEAD without a branch): every index path must still belong to
	// the checksum snapshot.
	for _, addition := range indexAdditions {
		path := string(addition.Path)
		if !seen[path] {
			result = append(result, addition)
			seen[path] = true
		}
	}
	return result
}

func (repo GitRepo) trackedFilePaths() []string {
	branchName := repo.currentBranch()
	if len(branchName) == 0 {
		return make([]string, 0)
	}
	byteArray := repo.executeRepoCommand("git", "ls-tree", "-z", "--name-only", "-r", branchName)
	var trackedFilePaths []string
	for _, path := range strings.Split(string(byteArray), "\x00") {
		if path != "" {
			trackedFilePaths = append(trackedFilePaths, path)
		}
	}
	return trackedFilePaths
}

func (repo GitRepo) stagedFiles() []string {
	output := repo.fetchStagedChanges()
	if len(output) == 0 {
		return []string{}
	}

	stagedFiles := strings.Split(output, "\x00")
	var result []string
	for index := 0; index < len(stagedFiles); {
		changeType := stagedFiles[index]
		index++
		if changeType == "" {
			continue
		}
		if index >= len(stagedFiles) {
			break
		}

		file := stagedFiles[index]
		index++
		if strings.HasPrefix(changeType, "R") || strings.HasPrefix(changeType, "C") {
			// For renames and copies the destination is the path that
			// exists in the staged snapshot.
			if index >= len(stagedFiles) {
				break
			}
			file = stagedFiles[index]
			index++
		}
		result = append(result, file)
	}
	return result
}

func (repo GitRepo) currentBranch() string {
	if !repo.hasBranch() {
		return ""
	}
	byteArray := repo.executeRepoCommand("git", "rev-parse", "--abbrev-ref", "HEAD")
	branchName := strings.TrimSpace(string(byteArray))
	return branchName
}

func (repo GitRepo) hasBranch() bool {
	byteArray := repo.executeRepoCommand("git", "branch")
	return len(string(byteArray)) != 0
}

func (repo GitRepo) outgoingNonDeletedFiles(oldCommit, newCommit string) []string {
	allChanges := strings.Split(repo.fetchRawOutgoingDiff(oldCommit, newCommit), "\x00")
	var result []string
	for _, c := range allChanges {
		if len(c) != 0 {
			result = append(result, c)
		}
	}
	return result
}

func (repo *GitRepo) fetchStagedChanges() string {
	return string(repo.executeRepoCommand(
		"git",
		"-c", "core.quotePath=false",
		"diff",
		"--cached",
		"--name-status",
		"-z",
		"--diff-filter=ACMR",
		"--find-renames",
	))
}

// extractAdditions will accept git diff --staged {file} output and filters the command output
// to get only the modified sections of the file
func (repo *GitRepo) extractAdditions(diffContent string) []byte {
	var result []byte
	changes := strings.Split(diffContent, "\n")
	for _, c := range changes {
		if !strings.HasPrefix(c, "+++") && !strings.HasPrefix(c, "---") && strings.HasPrefix(c, "+") {

			result = append(result, strings.TrimPrefix(c, "+")...)
			result = append(result, "\n"...)
		}
	}
	return result
}

func (repo GitRepo) fetchRawOutgoingDiff(oldCommit string, newCommit string) string {
	gitRange := oldCommit + ".." + newCommit
	return string(repo.executeRepoCommand(
		"git",
		"-c", "core.quotePath=false",
		"diff",
		gitRange,
		"--name-only",
		"-z",
		"--diff-filter=ACMR",
		"--find-renames",
	))
}

func (repo GitRepo) executeRepoCommand(commandName string, args ...string) []byte {
	log.WithFields(log.Fields{
		"command": commandName,
		"args":    args,
	}).Debug("Building repo command")
	co, err := repo.rawExecuteRepoCommand(commandName, args...)
	logEntry := log.WithFields(log.Fields{
		"dir":     repo.root,
		"command": fmt.Sprintf("%s %s", commandName, strings.Join(args, " ")),
		"output":  string(co),
		"error":   err,
	})
	if err == nil {
		logEntry.Debug("Git command executed successfully")
	} else {
		logEntry.Fatal("Git command execution failed")
	}
	return co
}

func (repo GitRepo) rawExecuteRepoCommand(commandName string, args ...string) ([]byte, error) {
	return repo.makeRepoCommand(commandName, args...).CombinedOutput()
}

func (repo GitRepo) makeRepoCommand(commandName string, args ...string) *exec.Cmd {
	command := exec.Command(commandName, args...)
	command.Dir = repo.root
	return command
}

func (repo GitRepo) readRepoFile(fileName, prefix string) ([]byte, error) {
	path := filepath.Join(repo.root, fileName)
	log.Debugf("reading file %s", path)
	fileExpression := fmt.Sprintf("%s:%s", prefix, fileName)
	return repo.rawExecuteRepoCommand("git", "cat-file", "-p", fileExpression)
}
