package main

import (
	"bufio"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"talisman/gitrepo"
)

const (
	//EmptySha represents the state of a brand new ref
	EmptySha string = "0000000000000000000000000000000000000000"
	//ShaId of the empty tree in Git
	EmptyTreeSha string = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
)

// pushRef represents a single outgoing ref handed to the pre-push hook on stdin.
// Git invokes the pre-push hook once for an entire `git push` and writes one
// line per outgoing ref in the form: <local ref> <local sha> <remote ref> <remote sha>
type pushRef struct {
	localRef, localCommit, remoteRef, remoteCommit string
}

type PrePushHook struct {
	refs []pushRef
	*runner
}

func NewPrePushHook(stdin io.Reader) *PrePushHook {
	prePushHook := &PrePushHook{
		readRefsAndShas(stdin),
		NewRunner(nil, PrePush)}
	prePushHook.additions = prePushHook.getRepoAdditions()
	return prePushHook
}

// getRepoAdditions collects every addition from every outgoing ref of the push
// into one shared generation so that a failure on any ref cannot be hidden by
// another ref being checked first. Additions are de-duplicated by path: a file
// reachable from several refs (common when a push contains multiple branches or
// tags sharing commits, or when the push is retried) is validated exactly once
// and must not pollute the report with repeated entries. Deleted refs contribute
// no additions and therefore cannot contaminate the batch either.
func (p *PrePushHook) getRepoAdditions() []gitrepo.Addition {
	seenPaths := make(map[gitrepo.FilePath]bool)
	var additions []gitrepo.Addition

	for _, ref := range p.refs {
		for _, addition := range ref.getRepoAdditions() {
			if seenPaths[addition.Path] {
				log.WithFields(log.Fields{
					"localRef": ref.localRef,
					"filePath": addition.Path,
				}).Info("Skipping addition already validated by another outgoing ref.")
				continue
			}
			seenPaths[addition.Path] = true
			additions = append(additions, addition)
		}
	}

	return additions
}

// If the outgoing ref does not exist on the remote, all commits on the local ref will be checked
// If the outgoing ref already exists, all additions in the range between "localSha" and "remoteSha" will be validated
func (ref pushRef) getRepoAdditions() []gitrepo.Addition {
	if ref.runningOnDeletedRef() {
		log.WithFields(log.Fields{
			"localRef":     ref.localRef,
			"localCommit":  ref.localCommit,
			"remoteRef":    ref.remoteRef,
			"remoteCommit": ref.remoteCommit,
		}).Info("Running on a deleted ref. Nothing to verify as outgoing changes are all deletions.")

		return []gitrepo.Addition{}
	}

	if ref.runningOnNewRef() {
		log.WithFields(log.Fields{
			"localRef":     ref.localRef,
			"localCommit":  ref.localCommit,
			"remoteRef":    ref.remoteRef,
			"remoteCommit": ref.remoteCommit,
		}).Info("Running on a new ref. All changes in the ref will be verified.")

		return ref.getRepoAdditionsFrom(EmptyTreeSha, ref.localCommit)
	}

	log.WithFields(log.Fields{
		"localRef":     ref.localRef,
		"localCommit":  ref.localCommit,
		"remoteRef":    ref.remoteRef,
		"remoteCommit": ref.remoteCommit,
	}).Info("Running on an existing ref. All changes in the commit range will be validated.")

	return ref.getRepoAdditionsFrom(ref.remoteCommit, ref.localCommit)
}

func (ref pushRef) runningOnDeletedRef() bool {
	return ref.localCommit == EmptySha
}

func (ref pushRef) runningOnNewRef() bool {
	return ref.remoteCommit == EmptySha
}

func (ref pushRef) getRepoAdditionsFrom(oldCommit, newCommit string) []gitrepo.Addition {
	wd, _ := os.Getwd()
	repo := gitrepo.RepoLocatedAt(wd)
	return repo.AdditionsWithinRange(oldCommit, newCommit)
}

// readRefsAndShas parses every outgoing ref line that Git sends to the
// pre-push hook. A single push can contain many branches and tags, and each
// line describes one of them; validating only the first line lets secrets on
// the remaining refs slip through unchecked.
func readRefsAndShas(file io.Reader) []pushRef {
	refs := make([]pushRef, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		refsAndShas := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(refsAndShas) < 4 {
			continue
		}
		refs = append(refs, pushRef{
			localRef:     refsAndShas[0],
			localCommit:  refsAndShas[1],
			remoteRef:    refsAndShas[2],
			remoteCommit: refsAndShas[3],
		})
	}
	return refs
}

// readRefAndSha retains the single-ref parsing behaviour for callers that only
// inspect the first outgoing ref. Multi-ref pushes must use readRefsAndShas.
func readRefAndSha(file io.Reader) (string, string, string, string) {
	text, _ := bufio.NewReader(file).ReadString('\n')
	refsAndShas := strings.Split(strings.Trim(string(text), "\n"), " ")
	if len(refsAndShas) < 4 {
		return EmptySha, EmptySha, "", ""
	}
	return refsAndShas[0], refsAndShas[1], refsAndShas[2], refsAndShas[3]
}
