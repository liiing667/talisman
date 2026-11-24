package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"talisman/detector/helpers"
	"talisman/detector/severity"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateReportRedactsSecretButKeepsEvidenceAndCategories(t *testing.T) {
	secret := "password=super-secret-value"
	results := helpers.NewDetectionResults()
	evidence := helpers.NewEvidence("password_phrase_pattern", secret)
	results.FailWithEvidence("config/application.yaml", "filecontent", "Potential secret pattern : "+helpers.PublicEvidence(secret), []string{"commit-sha"}, severity.Low, &evidence)
	results.WarnWithEvidence("config/application.yaml", "filecontent", "Potential secret pattern : "+helpers.PublicEvidence(secret), []string{"commit-sha"}, severity.Low, &evidence)
	results.Ignore("config/application.yaml", "filecontent")

	reportDirectory := t.TempDir()
	reportPath, err := GenerateReport(results, reportDirectory)

	assert.NoError(t, err)
	reportBytes, err := os.ReadFile(filepath.Join(reportPath, "report.json"))
	assert.NoError(t, err)

	reportText := string(reportBytes)
	assert.Contains(t, reportText, "config/application.yaml")
	assert.Contains(t, reportText, "failure_list")
	assert.Contains(t, reportText, "warning_list")
	assert.Contains(t, reportText, "ignore_list")
	assert.Contains(t, reportText, "filecontent")
	assert.Contains(t, reportText, "password_phrase_pattern")
	assert.Contains(t, reportText, evidence.Fingerprint)
	assert.NotContains(t, reportText, secret)
	assert.NotContains(t, reportText, "super-secret")

	var decoded helpers.DetectionResults
	assert.NoError(t, json.Unmarshal(reportBytes, &decoded))
	assert.Len(t, decoded.Results, 1)
	assert.Len(t, decoded.Results[0].FailureList, 1)
	assert.Len(t, decoded.Results[0].WarningList, 1)
	assert.Len(t, decoded.Results[0].IgnoreList, 1)
	assert.Equal(t, evidence, *decoded.Results[0].FailureList[0].Evidence)
	assert.Equal(t, "filecontent", decoded.Results[0].FailureList[0].Category)
	assert.Equal(t, "filecontent", decoded.Results[0].WarningList[0].Category)
	assert.Equal(t, "filecontent", decoded.Results[0].IgnoreList[0].Category)
	assert.False(t, strings.Contains(decoded.Results[0].FailureList[0].Message, secret))
}
