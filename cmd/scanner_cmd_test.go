package main

import (
	"os"
	"path/filepath"
	"strings"
	"talisman/git_testing"
	"talisman/gitrepo"
	"talisman/talismanrc"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScannerCmdFailsWhenBlobExceedsMaxReadableSize(t *testing.T) {
	git_testing.DoInTempGitRepo(func(git *git_testing.GitTesting) {
		git.SetupBaselineFiles("simple-file")
		oversizedContents := strings.Repeat("a", gitrepo.DefaultMaxBlobSize+1)
		err := os.WriteFile(filepath.Join(git.Root(), "big-file.txt"), []byte(oversizedContents), 0644)
		assert.NoError(t, err)
		git.AddAndcommit("*", "added oversized file")
		os.Chdir(git.Root())

		scannerCmd := NewScannerCmd(true, &talismanrc.TalismanRC{}, git.Root())
		scannerCmd.Run()
		assert.Equal(t, 1, scannerCmd.exitStatus(), "Expected ScannerCmd.exitStatus() to return 1 since an oversized blob could not be scanned")
		assert.True(t, scannerCmd.results.HasFailures(), "Expected failures to be recorded for the oversized blob")
	})
}

func TestScannerCmdFailsWhenGitObjectCannotBeRead(t *testing.T) {
	git_testing.DoInTempGitRepo(func(git *git_testing.GitTesting) {
		git.SetupBaselineFiles("simple-file")
		git.CreateFileWithContents("corrupt-me.txt", "contents that will become unreadable")
		git.AddAndcommit("*", "added file that will lose its object")

		blobDetails := git.GetBlobDetails("corrupt-me.txt") // "<hash> corrupt-me.txt"
		blobHash := strings.Split(blobDetails, " ")[0]
		looseObjectPath := filepath.Join(git.Root(), ".git", "objects", blobHash[:2], blobHash[2:])
		assert.NoError(t, os.Remove(looseObjectPath), "expected to be able to remove the loose object to simulate corruption")
		os.Chdir(git.Root())

		scannerCmd := NewScannerCmd(true, &talismanrc.TalismanRC{}, git.Root())
		scannerCmd.Run()
		assert.Equal(t, 1, scannerCmd.exitStatus(), "Expected ScannerCmd.exitStatus() to return 1 since a git object could not be read")
	})
}

func TestScannerCmdRunsSuccessfully(t *testing.T) {
	git_testing.DoInTempGitRepo(func(git *git_testing.GitTesting) {
		git.SetupBaselineFiles("simple-file")
		git.CreateFileWithContents("some-dir/should-be-included.txt", "safeContents")
		git.AddAndcommit("*", "Start of Scan")
		os.Chdir(git.Root())

		scannerCmd := NewScannerCmd(true, &talismanrc.TalismanRC{}, git.Root())
		scannerCmd.Run()
		assert.Equal(t, 0, scannerCmd.exitStatus(), "Expected ScannerCmd.exitStatus() to return 0 since no secret is found")
	})
}

func TestScannerCmdDetectsSecretAndFails(t *testing.T) {
	git_testing.DoInTempGitRepo(func(git *git_testing.GitTesting) {
		git.SetupBaselineFiles("simple-file")
		git.CreateFileWithContents("some-dir/file-with-secret.txt", awsAccessKeyIDExample)
		git.AddAndcommit("*", "Initial Commit")
		git.RemoveFile("some-dir/file-with-secret.txt")
		git.AddAndcommit("*", "Removed secret")
		git.CreateFileWithContents("some-dir/safe-file.txt", "safeContents")
		git.AddAndcommit("*", "Start of Scan")
		os.Chdir(git.Root())

		scannerCmd := NewScannerCmd(false, &talismanrc.TalismanRC{}, git.Root())
		scannerCmd.Run()
		assert.Equal(t, 1, scannerCmd.exitStatus(), "Expected ScannerCmd.exitStatus() to return 1 since secret present in history")
	})
}

func TestScannerCmdAddingSecretKeyShouldExitZeroIfFileIsWithinConfiguredScope(t *testing.T) {
	git_testing.DoInTempGitRepo(func(git *git_testing.GitTesting) {
		git.SetupBaselineFiles("simple-file")
		git.CreateFileWithContents("go.sum", awsAccessKeyIDExample)
		git.CreateFileWithContents("go.mod", awsAccessKeyIDExample)
		git.AddAndcommit("*", "go sum file")
		os.Chdir(git.Root())

		tRC := &talismanrc.TalismanRC{ScopeConfig: []talismanrc.ScopeConfig{{ScopeName: "go"}}}
		scannerCmd := NewScannerCmd(false, tRC, git.Root())
		scannerCmd.Run()
		assert.Equal(t, 0, scannerCmd.exitStatus(), "Expected ScannerCmd.exitStatus() to return 0 since no secret is found")
	})
}

func TestScannerCmdDetectsSecretAndIgnoresWhileRunningInIgnoreHistoryModeWithValidIgnoreConf(t *testing.T) {
	git_testing.DoInTempGitRepo(func(git *git_testing.GitTesting) {
		git.SetupBaselineFiles("simple-file")
		git.CreateFileWithContents("go.sum", awsAccessKeyIDExample)
		git.CreateFileWithContents("go.mod", awsAccessKeyIDExample)
		git.AddAndcommit("*", "go sum file")
		os.Chdir(git.Root())

		tRC := &talismanrc.TalismanRC{
			FileIgnoreConfig: []talismanrc.FileIgnoreConfig{
				{FileName: "go.sum", Checksum: "582093519ae682d5170aecc9b935af7e90ed528c577ecd2c9dd1fad8f4924ab9"},
				{FileName: "go.mod", Checksum: "8a03b9b61c505ace06d590d2b9b4f4b6fa70136e14c26875ced149180e00d1af"},
			}}
		scannerCmd := NewScannerCmd(true, tRC, git.Root())
		scannerCmd.Run()
		assert.Equal(t, 0, scannerCmd.exitStatus(), "Expected ScannerCmd.exitStatus() to return 0 since secrets file ignore is enabled")
	})
}

func TestScannerCmdDetectsSecretWhileRunningNormalScanMode(t *testing.T) {
	git_testing.DoInTempGitRepo(func(git *git_testing.GitTesting) {
		git.SetupBaselineFiles("simple-file")
		git.CreateFileWithContents("go.sum", awsAccessKeyIDExample)
		git.CreateFileWithContents("go.mod", awsAccessKeyIDExample)
		git.AddAndcommit("*", "go sum file")
		os.Chdir(git.Root())

		tRC := &talismanrc.TalismanRC{
			FileIgnoreConfig: []talismanrc.FileIgnoreConfig{
				{FileName: "go.sum", Checksum: "582093519ae682d5170aecc9b935af7e90ed528c577ecd2c9dd1fad8f4924ab9"},
				{FileName: "go.mod", Checksum: "8a03b9b61c505ace06d590d2b9b4f4b6fa70136e14c26875ced149180e00d1af"},
			}}
		scannerCmd := NewScannerCmd(false, tRC, git.Root())
		scannerCmd.Run()
		assert.Equal(t, 1, scannerCmd.exitStatus(), "Expected ScannerCmd.exitStatus() to return 1 because file ignore is disabled when scanning history")
	})
}
