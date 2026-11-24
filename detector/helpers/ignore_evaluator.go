package helpers

import (
	"os"
	"talisman/checksumcalculator"
	"talisman/gitrepo"
	"talisman/talismanrc"
	"talisman/utility"
)

type IgnoreEvaluator interface {
	ShouldIgnore(addition gitrepo.Addition, detectorType string) bool
}

type scanAllAdditions struct{}

// Returns an IgnoreEvaluator that forces all files to be scanned, such as when scanning the history of a repo
func ScanHistoryEvaluator() IgnoreEvaluator {
	return &scanAllAdditions{}
}

// Returns false so that all additions are scanned
func (ie *scanAllAdditions) ShouldIgnore(gitrepo.Addition, string) bool {
	return false
}

type ignoreEvaluator struct {
	calculator checksumcalculator.ChecksumCalculator
	talismanRC *talismanrc.TalismanRC
}

// Returns an IgnoreEvaluator around the rules defined in the current .talismanrc file
func BuildIgnoreEvaluator(hasherMode string, talismanRC *talismanrc.TalismanRC, repo gitrepo.GitRepo) IgnoreEvaluator {
	wd, _ := os.Getwd()
	hasher := utility.MakeHasher(hasherMode, wd)
	allTrackedFiles := append(repo.TrackedFilesAsAdditions(), repo.StagedAdditions()...)
	calculator := checksumcalculator.NewChecksumCalculator(hasher, allTrackedFiles)
	return &ignoreEvaluator{calculator: calculator, talismanRC: talismanRC}
}

// ShouldIgnore returns true if the talismanRC indicates that a Detector should ignore an Addition
func (ie *ignoreEvaluator) ShouldIgnore(addition gitrepo.Addition, detectorType string) bool {
	return ie.talismanRC.Deny(addition, detectorType) || ie.isScanNotRequired(addition)
}

// isScanNotRequired returns true if the Addition's current content is accepted by any
// file-wide checksum ignore rule in the .talismanrc file.
//
// Every matching rule is considered independently. A rule that is scoped to specific
// detectors is handled by Deny and must not disable the detectors it does not mention,
// even when its checksum matches. Similarly, a rule without a checksum does not express
// any accepted content identity and therefore cannot suppress scanning.
func (ie *ignoreEvaluator) isScanNotRequired(addition gitrepo.Addition) bool {
	for _, ignore := range ie.talismanRC.FileIgnoreConfig {
		if ignore.GetFileName() == "" || !addition.Matches(ignore.GetFileName()) {
			continue
		}
		if len(ignore.IgnoreDetectors) != 0 || ignore.Checksum == "" {
			continue
		}
		currentCollectiveChecksum := ie.calculator.CalculateCollectiveChecksumForPattern(ignore.GetFileName())
		if ignore.ChecksumMatches(currentCollectiveChecksum) {
			return true
		}
	}
	return false
}
