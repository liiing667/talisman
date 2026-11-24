package main

import (
	"fmt"
	"os"
	"talisman/detector"
	"talisman/detector/helpers"
	"talisman/detector/severity"
	"talisman/gitrepo"
	"talisman/prompt"
	"talisman/talismanrc"
)

// runner represents a single run of the validations for a given commit range
type runner struct {
	additions []gitrepo.Addition
	results   *helpers.DetectionResults
	mode      string
}

// NewRunner returns a new runner.
func NewRunner(additions []gitrepo.Addition, mode string) *runner {
	return &runner{
		additions: additions,
		results:   helpers.NewDetectionResults(),
		mode:      mode,
	}
}

// Run will validate the commit range for errors and return either COMPLETED_SUCCESSFULLY or COMPLETED_WITH_ERRORS
func (r *runner) Run(tRC *talismanrc.TalismanRC, promptContext prompt.PromptContext) int {
	wd, _ := os.Getwd()
	repo := gitrepo.RepoLocatedAt(wd)
	ie := helpers.BuildIgnoreEvaluator(r.mode, tRC, repo)

	setCustomSeverities(tRC)
	additionsToScan := tRC.RemoveScopedFiles(r.additions)

	detector.DefaultChain(tRC, ie).Test(additionsToScan, tRC, r.results)
	r.printReport(promptContext)
	exitStatus := r.exitStatus()
	return exitStatus
}

func setCustomSeverities(tRC *talismanrc.TalismanRC) {
	for _, cs := range tRC.CustomSeverities {
		severity.SeverityConfiguration[cs.Detector] = cs.Severity
	}
}

func (r *runner) printReport(promptContext prompt.PromptContext) {
	if r.results.HasWarnings() {
		fmt.Println(r.results.ReportWarnings())
	}
	if r.results.HasIgnores() || r.results.HasFailures() {
		r.results.ReportWithContent(promptContext, r.mode, r.capturedContents())
	}
}

// capturedContents returns the file bytes that were actually scanned. Pattern
// mode is the mode where an Addition holds the complete contents of a working
// tree file, so its checksum suggestion can be tied to exactly that snapshot.
func (r *runner) capturedContents() map[string][]byte {
	if r.mode != "pattern" {
		return nil
	}
	contents := make(map[string][]byte, len(r.additions))
	for _, addition := range r.additions {
		contents[string(addition.Path)] = addition.Data
	}
	return contents
}

func (r *runner) exitStatus() int {
	if r.results.HasFailures() {
		return EXIT_FAILURE
	}
	return EXIT_SUCCESS
}
