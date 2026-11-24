package main

import (
	"fmt"
	"os"
	"talisman/detector"
	"talisman/detector/helpers"
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
	results         *helpers.DetectionResults
	reportDirectory string
	ignoreEvaluator helpers.IgnoreEvaluator
	tRC             *talismanrc.TalismanRC
}

// Run scans git commit history for potential secrets and returns 0 or 1 as exit code
func (s *ScannerCmd) Run() int {
	fmt.Printf("\n\n")
	utility.CreateArt("Running Scan..")

	additionsToScan := s.tRC.RemoveScopedFiles(s.additions)

	detector.DefaultChain(s.tRC, s.ignoreEvaluator).Test(additionsToScan, s.tRC, s.results)
	reportsPath, err := report.GenerateReport(s.results, s.reportDirectory)
	if err != nil {
		logr.Errorf("error while generating report: %v", err)
		return EXIT_FAILURE
	}

	fmt.Printf("\nPlease check '%s' folder for the talisman scan report\n\n", reportsPath)
	if s.results.ScanStatus != nil && !s.results.ScanStatus.Completed {
		logr.Errorf("scan incomplete; failed %s %s: %s", s.results.ScanStatus.FailedObjectType, s.results.ScanStatus.FailedObject, s.results.ScanStatus.Error)
	}
	return s.exitStatus()
}

func (s *ScannerCmd) exitStatus() int {
	if s.results.ScanStatus != nil && !s.results.ScanStatus.Completed {
		return EXIT_FAILURE
	}
	if s.results.HasFailures() {
		return EXIT_FAILURE
	}
	return EXIT_SUCCESS
}

// NewScannerCmd Returns a new scanner command
func NewScannerCmd(ignoreHistory bool, tRC *talismanrc.TalismanRC, reportDirectory string) *ScannerCmd {
	repoRoot, _ := os.Getwd()
	reader := gitrepo.NewBatchGitObjectHashReader(repoRoot)
	additions, scanStatus, provenance := scanner.GetAdditionsWithStatus(ignoreHistory, reader)
	ignoreEvaluator := helpers.ScanHistoryEvaluator()
	if ignoreHistory {
		ignoreEvaluator = helpers.BuildIgnoreEvaluator("default", tRC, gitrepo.RepoLocatedAt(repoRoot))
	}
	results := helpers.NewDetectionResults()
	results.ScanStatus = &scanStatus
	results.Provenance = provenance
	results.CommitOrder = make(map[string]int, len(scanStatus.CommitOrder))
	for index, commit := range scanStatus.CommitOrder {
		results.CommitOrder[commit] = index
	}
	return &ScannerCmd{
		additions:       additions,
		results:         results,
		reportDirectory: reportDirectory,
		ignoreEvaluator: ignoreEvaluator,
		tRC:             tRC,
	}
}
