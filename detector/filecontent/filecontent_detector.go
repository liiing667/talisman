package filecontent

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"talisman/detector/helpers"
	"talisman/detector/severity"
	"talisman/gitrepo"
	"talisman/talismanrc"

	log "github.com/sirupsen/logrus"
)

type fn func(fc *FileContentDetector, word string) string

type FileContentDetector struct {
	base64Detector         *Base64Detector
	hexDetector            *HexDetector
	creditCardDetector     *CreditCardDetector
	base64EntropyThreshold float64
}

func NewFileContentDetector(tRC *talismanrc.TalismanRC) *FileContentDetector {
	fc := FileContentDetector{}
	fc.base64Detector = NewBase64Detector(tRC)
	fc.hexDetector = NewHexDetector()
	fc.creditCardDetector = NewCreditCardDetector()
	return &fc
}

func (fc *FileContentDetector) AggressiveMode() *FileContentDetector {
	fc.base64Detector.AggressiveDetector = &Base64AggressiveDetector{}
	return fc
}

type contentType int

const (
	base64Content contentType = iota
	hexContent
	creditCardContent
)

func (ct contentType) getInfo() string {
	switch ct {
	case base64Content:
		return "Base64Detector: Failing file as it contains a base64 encoded text."
	case hexContent:
		return "HexDetector: Failing file as it contains a hex encoded text."
	case creditCardContent:
		return "CreditCardDetector: Failing file as it contains a potential credit card number."
	}
	return ""
}

func (ct contentType) getMessageFormat() string {
	switch ct {
	case base64Content:
		return "Expected file to not contain base64 encoded texts such as: %s"
	case hexContent:
		return "Expected file to not contain hex encoded texts such as: %s"
	case creditCardContent:
		return "Expected file to not contain credit card numbers such as: %s"
	}

	return ""
}

type content struct {
	name        gitrepo.FileName
	path        gitrepo.FilePath
	contentType contentType
	results     []string
	severity    severity.Severity
}

func (fc *FileContentDetector) Test(comparator helpers.IgnoreEvaluator, currentAdditions []gitrepo.Addition, talismanRC *talismanrc.TalismanRC, result *helpers.DetectionResults, additionCompletionCallback func()) {
	contentTypes := []struct {
		contentType
		fn
		severity severity.Severity
	}{
		{
			contentType: base64Content,
			fn:          checkBase64,
			severity:    severity.SeverityConfiguration["Base64Content"],
		},
		{
			contentType: hexContent,
			fn:          checkHex,
			severity:    severity.SeverityConfiguration["HexContent"],
		},
		{
			contentType: creditCardContent,
			fn:          checkCreditCardNumber,
			severity:    severity.SeverityConfiguration["CreditCardContent"],
		},
	}
	re := regexp.MustCompile(`(?i)checksum[ \t]*:[ \t]*[0-9a-fA-F]+`)

	contents := make(chan content, 512)
	ignoredFilePaths := make(chan gitrepo.FilePath, len(currentAdditions))

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

			if string(addition.Name) == talismanrc.RCFileName {
				content := re.ReplaceAllString(string(addition.Data), "")
				data := []byte(content)
				addition.Data = data
			}
			addition.Data = []byte(talismanRC.RemoveAllowedPatterns(addition))
			for _, ct := range contentTypes {
				contents <- content{
					name:        addition.Name,
					path:        addition.Path,
					contentType: ct.contentType,
					results:     fc.detectFileOfType(addition.Data, ct.fn, ct.contentType),
					severity:    ct.severity,
				}
			}
		}(addition)
	}
	go func() {
		waitGroup.Wait()
		close(ignoredFilePaths)
		close(contents)
	}()
	for ignoredChanHasMore, contentChanHasMore := true, true; ignoredChanHasMore || contentChanHasMore; {
		select {
		case ignoredFilePath, hasMore := <-ignoredFilePaths:
			log.Debugf("Processing results for ignored file %v", ignoredFilePath)
			if !hasMore {
				ignoredChanHasMore = false
				continue
			}
			processIgnoredFilepath(ignoredFilePath, result)
		case c, hasMore := <-contents:
			log.Debugf("Processing results for file %v", c.path)
			if !hasMore {
				contentChanHasMore = false
				continue
			}
			processContent(c, talismanRC.Threshold, result)
		}
	}
}

func processIgnoredFilepath(path gitrepo.FilePath, result *helpers.DetectionResults) {
	log.WithFields(log.Fields{
		"filePath": path,
	}).Info("Ignoring addition as it was specified to be ignored.")
	result.Ignore(path, "filecontent")
}

func processContent(c content, threshold severity.Severity, result *helpers.DetectionResults) {
	for _, res := range c.results {
		if res != "" {
			log.WithFields(log.Fields{
				"filePath": c.path,
			}).Info(c.contentType.getInfo())
			if string(c.name) == talismanrc.RCFileName || !c.severity.ExceedsThreshold(threshold) {
				result.Warn(c.path, "filecontent", fmt.Sprintf(c.contentType.getMessageFormat(), formatForReporting(res)), []string{}, c.severity)
			} else {
				result.Fail(c.path, "filecontent", fmt.Sprintf(c.contentType.getMessageFormat(), formatForReporting(res)), []string{}, c.severity)
			}
		}
	}
}

func formatForReporting(input string) string {
	if len(input) > 50 {
		return input[:47] + "..."
	}
	return input
}

func (fc *FileContentDetector) detectFile(data []byte, getResult fn) []string {
	content := string(data)
	return fc.checkEachLine(content, getResult)
}

func (fc *FileContentDetector) detectFileOfType(data []byte, getResult fn, ct contentType) []string {
	content := string(data)
	return fc.checkEachLineOfType(content, getResult, ct)
}

func (fc *FileContentDetector) checkEachLine(content string, getResult fn) []string {
	lines := strings.Split(content, "\n")
	res := []string{}
	for _, line := range lines {
		lineResult := fc.checkEachWord(line, getResult)
		if len(lineResult) > 0 {
			res = append(res, lineResult...)
		}
	}
	return res
}

func (fc *FileContentDetector) checkEachLineOfType(content string, getResult fn, ct contentType) []string {
	lines := strings.Split(content, "\n")

	coveredByWrappedValue := make([]bool, len(lines))
	wrappedResults := map[int]string{}
	if ct == base64Content || ct == hexContent {
		for _, finding := range fc.findWrappedEncodings(lines, getResult, ct) {
			wrappedResults[finding.start] = finding.result
			for index := finding.start; index < finding.end; index++ {
				coveredByWrappedValue[index] = true
			}
		}
	}

	perLineResults := make([][]string, len(lines))
	for index, line := range lines {
		if coveredByWrappedValue[index] {
			continue
		}
		perLineResults[index] = fc.checkEachWord(line, getResult)
	}

	res := []string{}
	for index := range lines {
		if result, ok := wrappedResults[index]; ok {
			res = append(res, result)
			continue
		}
		if coveredByWrappedValue[index] {
			continue
		}
		res = append(res, perLineResults[index]...)
	}
	return res
}

type wrappedFinding struct {
	start  int
	end    int
	result string
}

// findWrappedEncodings reassembles encoded blobs that are split over several
// lines. The scanner normally tokenises by line and whitespace, which leaves it
// looking at individual fragments of a MIME-wrapped base64/hex value. Only
// lines that consist solely of the relevant encoding alphabet are considered.
// A successfully decoded block replaces the per-line findings for that block
// so one wrapped value produces one finding rather than a report per fragment.
func (fc *FileContentDetector) findWrappedEncodings(lines []string, getResult fn, ct contentType) []wrappedFinding {
	findings := []wrappedFinding{}
	for index := 0; index < len(lines); {
		if !isWrappedEncodingLine(lines[index], ct) {
			index++
			continue
		}

		var joined strings.Builder
		next := index
		for next < len(lines) && isWrappedEncodingLine(lines[next], ct) {
			trimmed := strings.TrimSpace(lines[next])
			if joined.Len()+len(trimmed) > maxNestedEncodedBytes {
				break
			}
			joined.WriteString(trimmed)
			next++
			if strings.Contains(trimmed, "=") {
				break
			}
		}

		if next-index >= 2 {
			encoded := joined.String()
			if wrappedValueExceedsBudget(encoded, ct) {
				// Decoding this block would exceed the nested-decoding
				// expansion budget. Report the original encoded text rather
				// than allocating it or silently passing the file.
				findings = append(findings, wrappedFinding{start: index, end: next, result: encoded})
			} else if validWrappedEncoding(encoded, ct) {
				if result := getResult(fc, encoded); result != "" {
					findings = append(findings, wrappedFinding{start: index, end: next, result: result})
				}
			}
		}

		if next == index {
			index++
		} else {
			index = next
		}
	}
	return findings
}

func isWrappedEncodingLine(line string, ct contentType) bool {
	trimmed := strings.TrimSpace(line)
	minLength := 4
	if ct == hexContent {
		minLength = 2
	}
	if len(trimmed) < minLength || len(trimmed) > 4096 {
		return false
	}
	switch ct {
	case base64Content:
		return isBase64Alphabet(trimmed) && !strings.Contains(strings.TrimRight(trimmed, "="), "=")
	case hexContent:
		return isHexAlphabet(trimmed)
	}
	return false
}

func validWrappedEncoding(encoded string, ct contentType) bool {
	switch ct {
	case base64Content:
		decoded, ok := decodeBase64String(encoded)
		// Only treat adjacent lines as one wrapped value when their
		// concatenation is textual. Otherwise independent encoded values that
		// happen to sit on consecutive lines (for example a hex value followed
		// by a base64 value) are merged and their individual findings are lost.
		return ok && isNestedText(decoded)
	case hexContent:
		_, ok := decodeHexString(encoded)
		return ok
	}
	return false
}

func wrappedValueExceedsBudget(encoded string, ct contentType) bool {
	condensed := stripEncodingWhitespace(encoded)
	switch ct {
	case base64Content:
		return len(condensed)*3/4 > maxNestedExpandedBytes
	case hexContent:
		return len(condensed)/2 > maxNestedExpandedBytes
	}
	return false
}

func (fc *FileContentDetector) checkEachWord(line string, getResult fn) []string {
	words := strings.Fields(line)
	res := []string{}
	for _, word := range words {
		wordResult := getResult(fc, word)
		if wordResult != "" {
			res = append(res, wordResult)
		}
	}
	return res
}

func checkBase64(fc *FileContentDetector, word string) string {
	return fc.base64Detector.CheckBase64Encoding(word)
}

func checkCreditCardNumber(fc *FileContentDetector, word string) string {
	return fc.creditCardDetector.checkCreditCardNumber(word)
}

func checkHex(fc *FileContentDetector, word string) string {
	return fc.hexDetector.CheckHexEncoding(word)
}
