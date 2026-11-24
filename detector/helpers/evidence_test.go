package helpers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPublicEvidenceDoesNotRevealSecretMaterial(t *testing.T) {
	secret := "password=super-secret-value"

	publicEvidence := PublicEvidence(secret)

	assert.NotContains(t, publicEvidence, "super")
	assert.NotContains(t, publicEvidence, "secret-value")
	assert.Equal(t, strings.Repeat("*", len(secret)), publicEvidence)
	assert.LessOrEqual(t, len(publicEvidence), maximumPublicEvidenceLength)
}

func TestLongPublicEvidenceIsTruncated(t *testing.T) {
	secret := "password=" + strings.Repeat("a", 100)

	publicEvidence := PublicEvidence(secret)

	assert.Equal(t, strings.Repeat("*", maximumPublicEvidenceLength-len(redactedEvidenceSuffix))+redactedEvidenceSuffix, publicEvidence)
	assert.Len(t, publicEvidence, maximumPublicEvidenceLength)
}

func TestNewEvidenceUsesDeterministicNonReversibleFingerprint(t *testing.T) {
	secret := "password=super-secret-value"

	firstEvidence := NewEvidence("password_phrase_pattern", secret)
	secondEvidence := NewEvidence("password_phrase_pattern", secret)

	assert.Equal(t, firstEvidence, secondEvidence)
	assert.Equal(t, "password_phrase_pattern", firstEvidence.Rule)
	assert.Len(t, firstEvidence.Fingerprint, 64)
	assert.NotContains(t, firstEvidence.Fingerprint, secret)
	assert.Equal(t, firstEvidence.Fingerprint, secondEvidence.Fingerprint)
}

func TestDetailsJSONContainsEvidenceAndNoSecret(t *testing.T) {
	secret := "password=super-secret-value"
	evidence := NewEvidence("password_phrase_pattern", secret)
	details := Details{
		Category: "filecontent",
		Message:  "Potential secret pattern : " + PublicEvidence(secret),
		Evidence: &evidence,
	}

	jsonBytes, err := json.Marshal(details)

	assert.NoError(t, err)
	jsonText := string(jsonBytes)
	assert.Contains(t, jsonText, "evidence")
	assert.Contains(t, jsonText, "password_phrase_pattern")
	assert.Contains(t, jsonText, evidence.Fingerprint)
	assert.NotContains(t, jsonText, "super-secret-value")
}

func TestFailWithEvidenceKeepsDistinctSecretsWithIdenticalRedactedMessages(t *testing.T) {
	results := NewDetectionResults()
	firstSecret := "password=first-secret"
	secondSecret := "password=other-secret"
	firstEvidence := NewEvidence("password_phrase_pattern", firstSecret)
	secondEvidence := NewEvidence("password_phrase_pattern", secondSecret)

	results.FailWithEvidence("secret.txt", "filecontent", "Potential secret pattern : "+PublicEvidence(firstSecret), nil, 1, &firstEvidence)
	results.FailWithEvidence("secret.txt", "filecontent", "Potential secret pattern : "+PublicEvidence(secondSecret), nil, 1, &secondEvidence)

	failures := results.GetFailures("secret.txt")
	assert.Len(t, failures, 2)
	assert.Equal(t, firstEvidence.Fingerprint, failures[0].Evidence.Fingerprint)
	assert.Equal(t, secondEvidence.Fingerprint, failures[1].Evidence.Fingerprint)
}
