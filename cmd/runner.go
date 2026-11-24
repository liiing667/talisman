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

	restoreDefaultSeverities, err := applyCustomSeverities(tRC)
	if err != nil {
		fmt.Println(err)
		return EXIT_FAILURE
	}
	defer restoreDefaultSeverities()

	additionsToScan := tRC.RemoveScopedFiles(r.additions)

	detector.DefaultChain(tRC, ie).Test(additionsToScan, tRC, r.results)
	r.printReport(promptContext)
	exitStatus := r.exitStatus()
	return exitStatus
}

// applyCustomSeverities validates the custom severity overrides configured in
// .talismanrc and applies them only for the duration of the current run. It
// returns a function that restores the default severity configuration, so
// that overrides can never leak into subsequent scans within the same process.
func applyCustomSeverities(tRC *talismanrc.TalismanRC) (func(), error) {
	if err := tRC.ValidateCustomSeverities(); err != nil {
		return nil, fmt.Errorf("\n\x1b[1m\x1b[31mInvalid custom severity configuration in .talismanrc: %v\x1b[0m\x1b[0m", err)
	}
	defaultSeverityConfiguration := severity.DefaultSeverityConfiguration()
	for _, cs := range tRC.CustomSeverities {
		severity.SeverityConfiguration[cs.Detector] = cs.Severity
	}
	return func() { severity.SeverityConfiguration = defaultSeverityConfiguration }, nil
}

func (r *runner) printReport(promptContext prompt.PromptContext) {
	if r.results.HasWarnings() {
		fmt.Println(r.results.ReportWarnings())
	}
	if r.results.HasIgnores() || r.results.HasFailures() {
		r.results.Report(promptContext, r.mode)
	}
}

func (r *runner) exitStatus() int {
	if r.results.HasFailures() {
		return EXIT_FAILURE
	}
	return EXIT_SUCCESS
}
