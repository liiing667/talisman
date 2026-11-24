package main

import (
	"testing"

	"talisman/detector/severity"
	"talisman/talismanrc"

	"github.com/stretchr/testify/assert"
)

func TestApplyCustomSeveritiesAppliesOverrideAndRestoresDefaults(t *testing.T) {
	tRC := &talismanrc.TalismanRC{
		CustomSeverities: []talismanrc.CustomSeverityConfig{
			{Detector: "HexContent", Severity: severity.Low},
		},
	}

	restoreDefaultSeverities, err := applyCustomSeverities(tRC)
	assert.NoError(t, err)
	assert.Equal(t, severity.Low, severity.SeverityConfiguration["HexContent"], "override should be effective during the current run")

	restoreDefaultSeverities()
	assert.Equal(t, severity.High, severity.SeverityConfiguration["HexContent"], "override must not leak into subsequent runs")
}

func TestApplyCustomSeveritiesFailsClosedForUnknownDetector(t *testing.T) {
	tRC := &talismanrc.TalismanRC{
		CustomSeverities: []talismanrc.CustomSeverityConfig{
			{Detector: "NotARealDetector", Severity: severity.Low},
		},
	}

	_, err := applyCustomSeverities(tRC)
	assert.Error(t, err, "unknown detector in custom_severities should fail before scanning")
	assert.Equal(t, severity.High, severity.SeverityConfiguration["HexContent"], "failed validation must not modify severity configuration")
}

func TestApplyCustomSeveritiesFailsClosedForInvalidSeverityLevel(t *testing.T) {
	tRC := &talismanrc.TalismanRC{
		CustomSeverities: []talismanrc.CustomSeverityConfig{
			{Detector: "HexContent", Severity: severity.Severity(0)},
		},
	}

	_, err := applyCustomSeverities(tRC)
	assert.Error(t, err, "invalid severity level in custom_severities should fail before scanning")
	assert.Equal(t, severity.High, severity.SeverityConfiguration["HexContent"], "failed validation must not modify severity configuration")
}
