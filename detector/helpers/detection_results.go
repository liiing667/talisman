package helpers

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"talisman/detector/severity"
	"talisman/gitrepo"
	"talisman/prompt"
	"talisman/talismanrc"
	"talisman/utility"

	"github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"

	"github.com/olekukonko/tablewriter"
)

// Provenance types are re-exported here because the report lives in this
// package and callers commonly inspect the chain through the result object.
type BlobProvenance = gitrepo.BlobProvenance
type PathProvenance = gitrepo.PathProvenance
type ScanStatus = gitrepo.ScanStatus
type Provenance = gitrepo.BlobProvenance

type Details struct {
	Category string            `json:"type"`
	Message  string            `json:"message"`
	Commits  []string          `json:"commits"`
	Severity severity.Severity `json:"severity,omitempty"`
}

type ResultsDetails struct {
	Filename    gitrepo.FilePath `json:"filename"`
	FailureList []Details        `json:"failure_list"`
	WarningList []Details        `json:"warning_list"`
	IgnoreList  []Details        `json:"ignore_list"`
}

type FailureTypes struct {
	Filecontent int `json:"filecontent"`
	Filesize    int `json:"filesize"`
	Filename    int `json:"filename"`
	Warnings    int `json:"warnings"`
	Ignores     int `json:"ignores"`
}

type ResultsSummary struct {
	Types FailureTypes `json:"types"`
}

// DetectionResults represents all interesting information collected during a detection run.
// It serves as a collecting parameter for the tests performed by the various Detectors in the DetectorChain
// Currently, it keeps track of failures and ignored files.
// The results are grouped by FilePath for easy reporting of all detected problems with individual files.
type DetectionResults struct {
	Summary    ResultsSummary   `json:"summary"`
	Results    []ResultsDetails `json:"results"`
	Provenance []gitrepo.BlobProvenance `json:"provenance,omitempty"`
	ScanStatus *gitrepo.ScanStatus      `json:"scan_status,omitempty"`
	CommitOrder map[string]int          `json:"-"`
}

func (r *DetectionResults) getResultDetailsForFilePath(fileName gitrepo.FilePath) *ResultsDetails {
	for _, resultDetail := range r.Results {
		if resultDetail.Filename == fileName {
			return &resultDetail
		}
	}
	return nil
}

// NewDetectionResults is a new DetectionResults struct. It represents the pre-run state of a Detection run.
func NewDetectionResults() *DetectionResults {
	return &DetectionResults{
		Summary: ResultsSummary{
			FailureTypes{0, 0, 0, 0, 0},
		},
		Results: make([]ResultsDetails, 0),
	}
}

// Fail is used to mark the supplied FilePath as failing a detection for a supplied reason.
// Detectors are encouraged to provide context sensitive messages so that fixing the errors is made simple for the end user
// Fail may be called multiple times for each FilePath and the calls accumulate the provided reasons
func (r *DetectionResults) Fail(filePath gitrepo.FilePath, category string, message string, commits []string, severity severity.Severity) {
	isFilePresentInResults := false
	for resultIndex := 0; resultIndex < len(r.Results); resultIndex++ {
		if r.Results[resultIndex].Filename == filePath {
			isFilePresentInResults = true
			isEntryPresentForGivenCategoryAndMessage := false
			for detailIndex := 0; detailIndex < len(r.Results[resultIndex].FailureList); detailIndex++ {
				if strings.Compare(r.Results[resultIndex].FailureList[detailIndex].Category, category) == 0 && strings.Compare(r.Results[resultIndex].FailureList[detailIndex].Message, message) == 0 {
					isEntryPresentForGivenCategoryAndMessage = true
					r.Results[resultIndex].FailureList[detailIndex].Commits = mergeCommits(r.Results[resultIndex].FailureList[detailIndex].Commits, commits)
				}
			}
			if !isEntryPresentForGivenCategoryAndMessage {
				r.Results[resultIndex].FailureList = append(r.Results[resultIndex].FailureList, Details{category, message, mergeCommits(nil, commits), severity})
			}
		}
	}
	if !isFilePresentInResults {
		failureDetails := Details{category, message, mergeCommits(nil, commits), severity}
		resultDetails := ResultsDetails{
			Filename:    filePath,
			FailureList: make([]Details, 0),
			WarningList: make([]Details, 0),
			IgnoreList:  make([]Details, 0),
		}
		resultDetails.FailureList = append(resultDetails.FailureList, failureDetails)
		r.Results = append(r.Results, resultDetails)
	}
	r.updateResultsSummary(category, false)
}

func (r *DetectionResults) Warn(filePath gitrepo.FilePath, category string, message string, commits []string, severity severity.Severity) {
	isFilePresentInResults := false
	for resultIndex := 0; resultIndex < len(r.Results); resultIndex++ {
		if r.Results[resultIndex].Filename == filePath {
			isFilePresentInResults = true
			isEntryPresentForGivenCategoryAndMessage := false
			for detailIndex := 0; detailIndex < len(r.Results[resultIndex].WarningList); detailIndex++ {
				if strings.Compare(r.Results[resultIndex].WarningList[detailIndex].Category, category) == 0 && strings.Compare(r.Results[resultIndex].WarningList[detailIndex].Message, message) == 0 {
					isEntryPresentForGivenCategoryAndMessage = true
					r.Results[resultIndex].WarningList[detailIndex].Commits = mergeCommits(r.Results[resultIndex].WarningList[detailIndex].Commits, commits)
				}
			}
			if !isEntryPresentForGivenCategoryAndMessage {
				r.Results[resultIndex].WarningList = append(r.Results[resultIndex].WarningList, Details{category, message, mergeCommits(nil, commits), severity})
			}
		}
	}
	if !isFilePresentInResults {
		warningDetails := Details{category, message, mergeCommits(nil, commits), severity}
		resultDetails := ResultsDetails{
			Filename:    filePath,
			FailureList: make([]Details, 0),
			WarningList: make([]Details, 0),
			IgnoreList:  make([]Details, 0),
		}
		resultDetails.WarningList = append(resultDetails.WarningList, warningDetails)
		r.Results = append(r.Results, resultDetails)
	}
	r.Summary.Types.Warnings++
}

// Ignore is used to mark the supplied FilePath as being ignored.
// The most common reason for this is that the FilePath is Denied by the Ignores supplied to the Detector, however, Detectors may use more sophisticated reasons to ignore files.
func (r *DetectionResults) Ignore(filePath gitrepo.FilePath, category string) {

	isFilePresentInResults := false
	for resultIndex := 0; resultIndex < len(r.Results); resultIndex++ {
		if r.Results[resultIndex].Filename == filePath {
			isFilePresentInResults = true
			isEntryPresentForGivenCategory := false
			for detailIndex := 0; detailIndex < len(r.Results[resultIndex].IgnoreList); detailIndex++ {
				if strings.Compare(r.Results[resultIndex].IgnoreList[detailIndex].Category, category) == 0 {
					isEntryPresentForGivenCategory = true

				}
			}
			if !isEntryPresentForGivenCategory {
				detail := Details{category, "", make([]string, 0), severity.Low}
				r.Results[resultIndex].IgnoreList = append(r.Results[resultIndex].IgnoreList, detail)
			}
		}
	}
	if !isFilePresentInResults {
		ignoreDetails := Details{category, "", make([]string, 0), severity.Low}
		resultDetails := ResultsDetails{
			Filename:    filePath,
			FailureList: make([]Details, 0),
			WarningList: make([]Details, 0),
			IgnoreList:  make([]Details, 0),
		}
		resultDetails.IgnoreList = append(resultDetails.IgnoreList, ignoreDetails)
		r.Results = append(r.Results, resultDetails)
	}
	r.Summary.Types.Ignores++
}

func (r *DetectionResults) updateResultsSummary(category string, decr bool) {
	val := 1
	if decr {
		val = -1
	}
	switch category {
	case "filecontent":
		r.Summary.Types.Filecontent += val
	case "filename":
		r.Summary.Types.Filename += val
	case "filesize":
		r.Summary.Types.Filesize += val
	}
}

// mergeCommits combines commit lists without introducing duplicates.  The
// first occurrence wins so callers can preserve git-log order.
func mergeCommits(existing []string, additional []string) []string {
	if len(existing) == 0 && len(additional) == 0 {
		return existing
	}
	result := make([]string, 0, len(existing)+len(additional))
	seen := make(map[string]struct{}, len(existing)+len(additional))
	for _, commits := range [][]string{existing, additional} {
		for _, commit := range commits {
			if commit == "" {
				continue
			}
			if _, ok := seen[commit]; ok {
				continue
			}
			seen[commit] = struct{}{}
			result = append(result, commit)
		}
	}
	return result
}

func (r *DetectionResults) sortDetails(details []Details) {
	for index := range details {
		commits := mergeCommits(nil, details[index].Commits)
		sort.SliceStable(commits, func(i, j int) bool {
			leftOrder, leftKnown := r.CommitOrder[commits[i]]
			rightOrder, rightKnown := r.CommitOrder[commits[j]]
			if leftKnown && rightKnown {
				return leftOrder < rightOrder
			}
			if leftKnown != rightKnown {
				return leftKnown
			}
			return commits[i] < commits[j]
		})
		details[index].Commits = commits
	}
	sort.SliceStable(details, func(i, j int) bool {
		if details[i].Category != details[j].Category {
			return details[i].Category < details[j].Category
		}
		return details[i].Message < details[j].Message
	})
}

// Sort normalizes the result so reports are stable across runs.  It also links
// each result path back to the blob hashes in the provenance chain.
func (r *DetectionResults) Sort() {
	sort.SliceStable(r.Results, func(i, j int) bool {
		return r.Results[i].Filename < r.Results[j].Filename
	})

	for index := range r.Results {
		r.sortDetails(r.Results[index].FailureList)
		r.sortDetails(r.Results[index].WarningList)
		r.sortDetails(r.Results[index].IgnoreList)
	}

	sort.SliceStable(r.Provenance, func(i, j int) bool {
		return r.Provenance[i].BlobHash < r.Provenance[j].BlobHash
	})
	for index := range r.Provenance {
		sort.Strings(r.Provenance[index].Paths)
		commits := mergeCommits(nil, r.Provenance[index].Commits)
		sort.SliceStable(commits, func(i, j int) bool {
			leftOrder, leftKnown := r.CommitOrder[commits[i]]
			rightOrder, rightKnown := r.CommitOrder[commits[j]]
			if leftKnown && rightKnown {
				return leftOrder < rightOrder
			}
			if leftKnown != rightKnown {
				return leftKnown
			}
			return commits[i] < commits[j]
		})
		r.Provenance[index].Commits = commits
		r.Provenance[index].Paths = mergeCommits(nil, r.Provenance[index].Paths)
		sort.SliceStable(r.Provenance[index].PathCommits, func(i, j int) bool {
			return r.Provenance[index].PathCommits[i].Path < r.Provenance[index].PathCommits[j].Path
		})
		for pathIndex := range r.Provenance[index].PathCommits {
			pathCommits := mergeCommits(nil, r.Provenance[index].PathCommits[pathIndex].Commits)
			sort.SliceStable(pathCommits, func(i, j int) bool {
				leftOrder, leftKnown := r.CommitOrder[pathCommits[i]]
				rightOrder, rightKnown := r.CommitOrder[pathCommits[j]]
				if leftKnown && rightKnown {
					return leftOrder < rightOrder
				}
				if leftKnown != rightKnown {
					return leftKnown
				}
				return pathCommits[i] < pathCommits[j]
			})
			r.Provenance[index].PathCommits[pathIndex].Commits = pathCommits
		}
	}
}

// HasFailures answers if any Failures were detected for any FilePath in the current run
func (r *DetectionResults) HasFailures() bool {
	return r.Summary.Types.Filesize > 0 || r.Summary.Types.Filename > 0 || r.Summary.Types.Filecontent > 0
}

// HasIgnores answers if any FilePaths were ignored in the current run
func (r *DetectionResults) HasIgnores() bool {
	return r.Summary.Types.Ignores > 0
}

func (r *DetectionResults) HasWarnings() bool {
	return r.Summary.Types.Warnings > 0
}

func (r *DetectionResults) HasDetectionMessages() bool {
	return r.HasWarnings() || r.HasFailures() || r.HasIgnores()
}

// Successful answers if no detector was able to find any possible result to fail the run
func (r *DetectionResults) Successful() bool {
	return !r.HasFailures() && (r.ScanStatus == nil || r.ScanStatus.Completed)
}

// GetFailures returns the various reasons that a given FilePath was marked as failing by all the detectors in the current run
func (r *DetectionResults) GetFailures(fileName gitrepo.FilePath) []Details {
	results := r.getResultDetailsForFilePath(fileName)
	if results == nil {
		return []Details{}
	}
	return results.FailureList
}

func (r *DetectionResults) ReportWarnings() string {
	var data [][]string

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"File", "Warnings", "Severity"})
	table.SetRowLine(true)

	for _, resultDetails := range r.Results {
		if len(resultDetails.WarningList) > 0 {
			warningData := r.ReportFileWarnings(resultDetails.Filename)
			data = append(data, warningData...)
		}
	}

	results := strings.Builder{}
	if r.Summary.Types.Warnings > 0 {
		fmt.Printf("\n\x1b[1m\x1b[31mTalisman Warnings:\x1b[0m\x1b[0m\n")
		table.AppendBulk(data)
		table.Render()
		results.WriteString("\n\x1b[33mPlease review the above file(s) to make sure that no sensitive content is being pushed\x1b[0m\n\n")
	}
	return results.String()
}

// Report returns a string documenting the various failures and ignored files for the current run
func (r *DetectionResults) Report(promptContext prompt.PromptContext, mode string) string {
	var result string
	var filePathsForFailures []string
	var data [][]string

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"File", "Errors", "Severity"})
	table.SetRowLine(true)

	for _, resultDetails := range r.Results {
		if len(resultDetails.FailureList) > 0 {
			filePathsForFailures = append(filePathsForFailures, string(resultDetails.Filename))
			failureData := r.ReportFileFailures(resultDetails.Filename)
			data = append(data, failureData...)
		}
	}

	filePathsForFailures = utility.UniqueItems(filePathsForFailures)

	if r.HasFailures() {
		fmt.Printf("\n\x1b[1m\x1b[31mTalisman Report:\x1b[0m\x1b[0m\n")
		table.AppendBulk(data)
		table.Render()
		fmt.Println()
		r.suggestTalismanRC(filePathsForFailures, promptContext, mode)
	}
	return result
}

func (r *DetectionResults) suggestTalismanRC(filePaths []string, promptContext prompt.PromptContext, mode string) {
	var entriesToAdd []talismanrc.FileIgnoreConfig
	hasher := utility.MakeHasher(mode, ".")
	for _, filePath := range filePaths {
		currentChecksum := hasher.CollectiveSHA256Hash([]string{filePath})
		fileIgnoreConfig := talismanrc.IgnoreFileWithChecksum(filePath, currentChecksum)
		entriesToAdd = append(entriesToAdd, fileIgnoreConfig)
	}

	if promptContext.Interactive && runtime.GOOS != "windows" {
		confirmedEntries := getUserConfirmation(entriesToAdd, promptContext)
		talismanrcConfig, _ := talismanrc.Load()
		talismanrcConfig.AddIgnores(confirmedEntries)

		for _, confirmedEntry := range confirmedEntries {
			resultsDetails := r.getResultDetailsForFilePath(gitrepo.FilePath(confirmedEntry.GetFileName()))
			for _, failure := range resultsDetails.FailureList {
				r.updateResultsSummary(failure.Category, true)
			}
		}

		output, err := exec.Command("git", "add", ".talismanrc").CombinedOutput()
		if err != nil {
			logrus.Errorf("Error appending to talismanrc %v", output)
		}
	} else {
		printTalismanIgnoreSuggestion(entriesToAdd)
		return
	}

}

func getUserConfirmation(configs []talismanrc.FileIgnoreConfig, promptContext prompt.PromptContext) []talismanrc.FileIgnoreConfig {
	confirmed := []talismanrc.FileIgnoreConfig{}
	if len(configs) != 0 {
		fmt.Println("==== Interactively adding to talismanrc ====")
	}
	for _, config := range configs {
		if confirm(config, promptContext) {
			confirmed = append(confirmed, config)
		}
	}
	return confirmed
}

func printTalismanIgnoreSuggestion(entriesToAdd []talismanrc.FileIgnoreConfig) {
	ignoreEntries := talismanrc.SuggestRCFor(entriesToAdd)
	suggestString := fmt.Sprintf("\n\x1b[33mIf you are absolutely sure that you want to ignore the " +
		"above files from talisman detectors, consider pasting the following format in .talismanrc file" +
		" in the project root\x1b[0m\n")
	fmt.Println(suggestString)
	fmt.Println(ignoreEntries)
}

func confirm(config talismanrc.FileIgnoreConfig, promptContext prompt.PromptContext) bool {
	bytes, err := yaml.Marshal(&config)
	if err != nil {
		logrus.Errorf("error marshalling file ignore config: %s", err)
	}

	fmt.Println()
	fmt.Println(string(bytes))

	confirmationString := fmt.Sprintf("Do you want to add %s with above checksum in talismanrc ?", config.GetFileName())

	return promptContext.Prompt.Confirm(confirmationString)
}

// ReportFileFailures adds a string to table documenting the various failures detected on the supplied FilePath by all detectors in the current run
func (r *DetectionResults) ReportFileFailures(filePath gitrepo.FilePath) [][]string {
	failureList := r.getResultDetailsForFilePath(filePath).FailureList
	var data [][]string
	if len(failureList) > 0 {
		for _, detail := range failureList {
			if len(detail.Message) > 150 {
				detail.Message = detail.Message[:75] + "\n" + detail.Message[75:147] + "..."
			}
			data = append(data, []string{string(filePath), detail.Message, detail.Severity.String()})
		}
	}
	return data
}

func (r *DetectionResults) ReportFileWarnings(filePath gitrepo.FilePath) [][]string {
	warningList := r.getResultDetailsForFilePath(filePath).WarningList
	var data [][]string
	if len(warningList) > 0 {
		for _, detail := range warningList {
			if len(detail.Message) > 150 {
				detail.Message = detail.Message[:75] + "\n" + detail.Message[75:147] + "..."
			}
			data = append(data, []string{string(filePath), detail.Message, detail.Severity.String()})
		}
	}
	return data
}
