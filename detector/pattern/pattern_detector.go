package pattern

import (
	"fmt"
	"regexp"
	"sync"
	"talisman/detector/helpers"
	"talisman/detector/severity"
	"talisman/gitrepo"
	"talisman/talismanrc"

	log "github.com/sirupsen/logrus"
)

type PatternDetector struct {
	secretsPattern *PatternMatcher
}

var (
	detectorPatterns = []*severity.PatternSeverity{
		{Pattern: regexp.MustCompile(`(?i)((.*)(password|passphrase|secret|key|pwd|pword|pass)(.*) *[:=>,][^,;\n]{8,})`), Severity: severity.SeverityConfiguration["PasswordPhrasePattern"], RuleName: "password_phrase_pattern"},
		{Pattern: regexp.MustCompile(`(?i)((:)(password|passphrase|secret|key|pwd|pword|pass)(.*) *[ ][^,;\n]{8,})`), Severity: severity.SeverityConfiguration["PasswordPhrasePattern"], RuleName: "password_phrase_pattern"},
		{Pattern: regexp.MustCompile(`(?i)(['"_]?pw['"]? *[:=][^,;\n]{8,})`), Severity: severity.SeverityConfiguration["PasswordPhrasePattern"], RuleName: "password_phrase_pattern"},
		{Pattern: regexp.MustCompile(`(?i)(<ConsumerKey>\S*</ConsumerKey>)`), Severity: severity.SeverityConfiguration["ConsumerKeyPattern"], RuleName: "consumer_key_pattern"},
		{Pattern: regexp.MustCompile(`(?i)(<ConsumerSecret>\S*</ConsumerSecret>)`), Severity: severity.SeverityConfiguration["ConsumerSecretParrern"], RuleName: "consumer_secret_pattern"},
		{Pattern: regexp.MustCompile(`(?i)(AWS[ \w]+key[ \w]+[:=])`), Severity: severity.SeverityConfiguration["AWSKeyPattern"], RuleName: "aws_key_pattern"},
		{Pattern: regexp.MustCompile(`(?i)(AWS[ \w]+secret[ \w]+[:=])`), Severity: severity.SeverityConfiguration["AWSSecretPattern"], RuleName: "aws_secret_pattern"},
		{Pattern: regexp.MustCompile(`(?s)(BEGIN RSA PRIVATE KEY.*END RSA PRIVATE KEY)`), Severity: severity.SeverityConfiguration["RSAKeyPattern"], RuleName: "rsa_key_pattern"},
	}
)

type match struct {
	name       gitrepo.FileName
	path       gitrepo.FilePath
	commits    []string
	detections []DetectionsWithSeverity
}

const customPatternRuleName = "custom_pattern"

// Test tests the contents of the Additions to ensure that they don't look suspicious
func (detector PatternDetector) Test(comparator helpers.IgnoreEvaluator, currentAdditions []gitrepo.Addition, ignoreConfig *talismanrc.TalismanRC, result *helpers.DetectionResults, additionCompletionCallback func()) {
	matches := make(chan match, 512)
	ignoredFilePaths := make(chan gitrepo.FilePath, 512)
	waitGroup := &sync.WaitGroup{}
	waitGroup.Add(len(currentAdditions))
	for _, addition := range currentAdditions {
		go func(addition gitrepo.Addition) {
			defer waitGroup.Done()
			defer additionCompletionCallback()
			if comparator.ShouldIgnore(addition, "filecontent") {
				ignoredFilePaths <- addition.Path
				return
			}
			detections := detector.secretsPattern.check(ignoreConfig.RemoveAllowedPatterns(addition), ignoreConfig.Threshold)
			matches <- match{name: addition.Name, path: addition.Path, detections: detections, commits: addition.Commits}
		}(addition)
	}
	go func() {
		waitGroup.Wait()
		close(matches)
		close(ignoredFilePaths)
	}()
	for ignoredChanHasMore, matchChanHasMore := true, true; ignoredChanHasMore || matchChanHasMore; {
		select {
		case match, hasMore := <-matches:
			if !hasMore {
				matchChanHasMore = false
				continue
			}
			detector.processMatch(match, result, ignoreConfig.Threshold)
		case ignore, hasMore := <-ignoredFilePaths:
			if !hasMore {
				ignoredChanHasMore = false
				continue
			}
			detector.processIgnore(ignore, result)
		}
	}
}

func (detector PatternDetector) processIgnore(ignoredFilePath gitrepo.FilePath, result *helpers.DetectionResults) {
	log.WithFields(log.Fields{
		"filePath": ignoredFilePath,
	}).Info("Ignoring addition as it was specified to be ignored.")
	result.Ignore(ignoredFilePath, "filecontent")
}

func (detector PatternDetector) processMatch(match match, result *helpers.DetectionResults, threshold severity.Severity) {
	for _, detectionWithSeverity := range match.detections {
		for _, detection := range detectionWithSeverity.detections {
			if detection != "" {
				if string(match.name) == talismanrc.RCFileName || !detectionWithSeverity.severity.ExceedsThreshold(threshold) {
					log.WithFields(log.Fields{
						"filePath": match.path,
						"pattern":  helpers.PublicEvidence(detection),
					}).Warn("Warning file as it matched pattern.")
					evidence := helpers.NewEvidence(detectionWithSeverity.ruleName, detection)
					result.WarnWithEvidence(match.path, "filecontent", fmt.Sprintf("Potential secret pattern : %s", helpers.PublicEvidence(detection)), match.commits, detectionWithSeverity.severity, &evidence)
				} else {
					log.WithFields(log.Fields{
						"filePath": match.path,
						"pattern":  helpers.PublicEvidence(detection),
					}).Info("Failing file as it matched pattern.")
					evidence := helpers.NewEvidence(detectionWithSeverity.ruleName, detection)
					result.FailWithEvidence(match.path, "filecontent", fmt.Sprintf("Potential secret pattern : %s", helpers.PublicEvidence(detection)), match.commits, detectionWithSeverity.severity, &evidence)
				}
			}
		}
	}
}

// NewPatternDetector returns a PatternDetector that tests Additions against the pre-configured patterns
func NewPatternDetector(custom []talismanrc.PatternString) *PatternDetector {
	matcher := NewPatternMatcher(detectorPatterns)
	for _, pattern := range custom {
		matcher.add(pattern)
	}
	return &PatternDetector{matcher}
}
