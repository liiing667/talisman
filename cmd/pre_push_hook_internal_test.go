package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsingSingleRefShasFromStdIn(t *testing.T) {
	file := strings.NewReader("localRef localSha remoteRef remoteSha")

	_, oldSha, _, newSha := readRefAndSha(file)
	assert.Equal(t, "localSha", oldSha, "oldSha did not equal 'localSha', got: %s", oldSha)
	assert.Equal(t, "remoteSha", newSha, "newSha did not equal 'remoteSha', got: %s", newSha)
}

func TestParsingAllRefsFromMultiRefStdIn(t *testing.T) {
	file := strings.NewReader(strings.Join([]string{
		"refs/heads/first 1111111111111111111111111111111111111111 refs/heads/first 2222222222222222222222222222222222222222",
		"refs/heads/second 3333333333333333333333333333333333333333 refs/tags/v1 4444444444444444444444444444444444444444",
	}, "\n"))

	refs := readRefsAndShas(file)

	assert.Len(t, refs, 2, "Expected every outgoing ref line to be parsed")
	assert.Equal(t, pushRef{
		localRef:     "refs/heads/first",
		localCommit:  "1111111111111111111111111111111111111111",
		remoteRef:    "refs/heads/first",
		remoteCommit: "2222222222222222222222222222222222222222",
	}, refs[0])
	assert.Equal(t, pushRef{
		localRef:     "refs/heads/second",
		localCommit:  "3333333333333333333333333333333333333333",
		remoteRef:    "refs/tags/v1",
		remoteCommit: "4444444444444444444444444444444444444444",
	}, refs[1], "Expected refs after the first line to be parsed instead of being ignored")
}

func TestParsingSingleRefFromStdInStaysCompatible(t *testing.T) {
	file := strings.NewReader("master localSha master remoteSha\n")

	refs := readRefsAndShas(file)

	assert.Len(t, refs, 1)
	assert.Equal(t, "master", refs[0].localRef)
	assert.Equal(t, "localSha", refs[0].localCommit)
	assert.Equal(t, "master", refs[0].remoteRef)
	assert.Equal(t, "remoteSha", refs[0].remoteCommit)
}

func TestParsingEmptyStdInReturnsNoRefs(t *testing.T) {
	refs := readRefsAndShas(strings.NewReader(""))

	assert.Empty(t, refs, "Expected no refs to be parsed when stdin has no outgoing changes")
}

func TestParsingMalformedLinesIsSkipped(t *testing.T) {
	file := strings.NewReader(strings.Join([]string{
		"only three fields",
		"refs/heads/branch 1111111111111111111111111111111111111111 refs/heads/branch 2222222222222222222222222222222222222222",
		"",
	}, "\n"))

	refs := readRefsAndShas(file)

	assert.Len(t, refs, 1, "Expected malformed and blank lines to be skipped without failing the push")
	assert.Equal(t, "refs/heads/branch", refs[0].localRef)
}

func TestParsingDeletedRef(t *testing.T) {
	file := strings.NewReader("refs/heads/removed " + EmptySha + " refs/heads/removed " + "1111111111111111111111111111111111111111\n")

	refs := readRefsAndShas(file)

	assert.Len(t, refs, 1)
	assert.True(t, refs[0].runningOnDeletedRef())
	assert.False(t, refs[0].runningOnNewRef())
}

func TestParsingNewRef(t *testing.T) {
	file := strings.NewReader("refs/heads/new 1111111111111111111111111111111111111111 refs/heads/new " + EmptySha + "\n")

	refs := readRefsAndShas(file)

	assert.Len(t, refs, 1)
	assert.True(t, refs[0].runningOnNewRef())
	assert.False(t, refs[0].runningOnDeletedRef())
}
