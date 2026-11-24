package helpers

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	maximumPublicEvidenceLength = 47
	redactedEvidenceSuffix      = "..."
)

// Evidence contains only the information that is safe to expose in reports.
// Fingerprint is a deterministic hash of the original evidence and never contains secret material.
type Evidence struct {
	Rule        string `json:"rule"`
	Fingerprint string `json:"fingerprint"`
}

// NewEvidence builds a public evidence record for a detector rule and its original matched content.
func NewEvidence(rule string, secret string) Evidence {
	hash := sha256.Sum256([]byte(secret))
	return Evidence{
		Rule:        rule,
		Fingerprint: hex.EncodeToString(hash[:]),
	}
}

// PublicEvidence returns a non-reversible, truncated form of matched content for reports.
func PublicEvidence(secret string) string {
	runes := []rune(secret)
	if len(runes) <= maximumPublicEvidenceLength {
		return RedactedEvidence(secret)
	}
	return RedactedEvidence(string(runes[:maximumPublicEvidenceLength-len(redactedEvidenceSuffix)])) + redactedEvidenceSuffix
}

// RedactedEvidence replaces every character in matched content so the original cannot be reconstructed.
func RedactedEvidence(secret string) string {
	return strings.Repeat("*", len([]rune(secret)))
}
