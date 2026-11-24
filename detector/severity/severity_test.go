package severity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldReturnSeverityStringForDefinedSeverity(t *testing.T) {
	assert.Equal(t, String(Low), "low")
	assert.Equal(t, String(Medium), "medium")
	assert.Equal(t, String(High), "high")
}
func TestShouldReturnEmptyForInvalidSeverity(t *testing.T) {
	assert.Equal(t, String(10), "")
}

func TestShouldReturnSeverityForDefinedStrings(t *testing.T) {
	severityValue, _ := FromString("low")
	assert.Equal(t, severityValue, Low)
	severityValue, _ = FromString("mEDIum")
	assert.Equal(t, severityValue, Medium)
	severityValue, _ = FromString("HIGH")
	assert.Equal(t, severityValue, High)
}

func TestShouldReturnSeverityZeroWithErrorForUnknownStrings(t *testing.T) {
	severityValue, err := FromString("FakeSeverity")
	assert.Equal(t, Severity(0), severityValue)
	assert.Error(t, err)
	assert.Equal(t, "unknown severity FakeSeverity", err.Error())
}

func TestDefaultSeverityConfigurationShouldMatchBuiltInConfiguration(t *testing.T) {
	defaults := DefaultSeverityConfiguration()
	assert.Equal(t, SeverityConfiguration, defaults)
	assert.Equal(t, High, defaults["HexContent"])
}

func TestDefaultSeverityConfigurationShouldBeIndependentOfBuiltInConfiguration(t *testing.T) {
	defaults := DefaultSeverityConfiguration()
	defaults["HexContent"] = Low
	assert.Equal(t, High, SeverityConfiguration["HexContent"], "mutating the returned copy must not mutate the built-in defaults")
}

func TestShouldAcceptCustomSeverityForKnownDetectorAndValidLevel(t *testing.T) {
	for _, severityValue := range []Severity{Low, Medium, High} {
		assert.NoError(t, ValidateCustomSeverity("HexContent", severityValue))
	}
}

func TestShouldRejectCustomSeverityForUnknownDetector(t *testing.T) {
	err := ValidateCustomSeverity("NotARealDetector", Low)
	assert.Error(t, err)
	assert.Equal(t, `unknown detector "NotARealDetector" in custom severity configuration`, err.Error())
}

func TestShouldRejectCustomSeverityForInvalidLevel(t *testing.T) {
	assert.Error(t, ValidateCustomSeverity("HexContent", Severity(0)), "severity zero (e.g. missing level in .talismanrc) must fail closed")
	assert.Error(t, ValidateCustomSeverity("HexContent", Severity(10)))
}
