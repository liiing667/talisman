package main

import (
	"errors"
	"fmt"
	"os"
	"talisman/detector"
	"talisman/detector/helpers"
	"talisman/detector/severity"
	"talisman/gitrepo"
	"talisman/report"
	"talisman/scanner"
	"talisman/talismanrc"
	"talisman/utility"

	logr "github.com/sirupsen/logrus"
)

const (
	SCAN_MODE = "scan"
)

type ScannerCmd struct {
	additions       []gitrepo.Addition
	readErrors      []scanner.BlobReadError
	results         *helpers.DetectionResults
	reportDirectory string
	ignoreEvaluator helpers.IgnoreEvaluator
	tRC             *talismanrc.TalismanRC
}

// Run scans git commit history for potential secrets and returns 0 or 1 as exit code
func (s *ScannerCmd) Run() int {
	fmt.Printf("\n\n")
	utility.CreateArt("Running Scan..")

	s.recordBlobReadErrors()

	additionsToScan := s.tRC.RemoveScopedFiles(s.additions)

	detector.DefaultChain(s.tRC, s.ignoreEvaluator).Test(additionsToScan, s.tRC, s.results)
	reportsPath, err := report.GenerateReport(s.results, s.reportDirectory)
	if err != nil {
		logr.Errorf("error while generating report: %v", err)
		return EXIT_FAILURE
	}

	fmt.Printf("\nPlease check '%s' folder for the talisman scan report\n\n", reportsPath)
	return s.exitStatus()
}

// recordBlobReadErrors turns blobs that could not be read while scanning the
// history into failures, so that a partially read repository never produces a
// success report.
func (s *ScannerCmd) recordBlobReadErrors() {
	for _, readError := range s.readErrors {
		logr.Errorf("unable to scan file %q: %v", readError.Path, readError.Err)
		category := "error"
		if errors.Is(readError.Err, gitrepo.ErrBlobTooLarge) {
			category = "filesize"
		}
		s.results.Fail(gitrepo.FilePath(readError.Path), category, fmt.Sprintf("The file %q could not be scanned: %v", readError.Path, readError.Err), readError.Commits, severity.High)
	}
}

func (s *ScannerCmd) exitStatus() int {
	if s.results.HasFailures() || len(s.readErrors) > 0 {
		return EXIT_FAILURE
	}
	return EXIT_SUCCESS
}

// NewScannerCmd Returns a new scanner command
func NewScannerCmd(ignoreHistory bool, tRC *talismanrc.TalismanRC, reportDirectory string) *ScannerCmd {
	repoRoot, _ := os.Getwd()
	reader := gitrepo.NewBatchGitObjectHashReader(repoRoot)
	additions, readErrors := scanner.GetAdditions(ignoreHistory, reader)
	ignoreEvaluator := helpers.ScanHistoryEvaluator()
	if ignoreHistory {
		ignoreEvaluator = helpers.BuildIgnoreEvaluator("default", tRC, gitrepo.RepoLocatedAt(repoRoot))
	}
	return &ScannerCmd{
		additions:       additions,
		readErrors:      readErrors,
		results:         helpers.NewDetectionResults(),
		reportDirectory: reportDirectory,
		ignoreEvaluator: ignoreEvaluator,
		tRC:             tRC,
	}
}
