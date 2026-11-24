package filecontent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"talisman/detector/helpers"
	"talisman/gitrepo"
	"talisman/talismanrc"
	"testing"

	"github.com/stretchr/testify/assert"
)

// This control is deliberately shared by the positive and negative cases
// below. It has entropy above the base64 threshold but is rejected by the
// word check, so it marks the existing false-positive boundary. The wrapped
// secret case proves that the boundary is only crossed after a real encoded
// payload has been peeled, not merely because nested decoding is enabled.
const nestedDecodeBoundaryControl = "TestBase64DetectorShouldNotDetectLongMethodNamesEvenWithRidiculousHighEntropyWordsMightExist"

func scanNestedDecodingTestContent(t *testing.T, content string) []string {
	t.Helper()
	results := helpers.NewDetectionResults()
	additions := []gitrepo.Addition{gitrepo.NewAddition(filename, []byte(content))}

	NewFileContentDetector(emptyTalismanRC).
		Test(defaultIgnoreEvaluator, additions, emptyTalismanRC, results, dummyCallback)

	if !results.HasFailures() {
		return nil
	}
	return getFailureMessages(results, additions[0].Path)
}

func TestNestedDecodeBoundaryControlRemainsSafe(t *testing.T) {
	if messages := scanNestedDecodingTestContent(t, nestedDecodeBoundaryControl); len(messages) != 0 {
		t.Fatalf("expected the fixed high-entropy control to stay below the detection boundary, got %v", messages)
	}

	bd := NewBase64Detector(&talismanrc.TalismanRC{})
	assert.Equal(t, "", bd.CheckBase64Encoding(nestedDecodeBoundaryControl))
}

func TestNestedBase64WrappedHexSecretIsDetectedWithoutLeakingDecodedValue(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	hexEncoded := hex.EncodeToString([]byte(secret))
	base64AndHexEncoded := base64.StdEncoding.EncodeToString([]byte(hexEncoded))

	// The outer value is below the base64 entropy threshold, which is why it
	// previously escaped single-layer detection. Nested decoding must now
	// reach the hex layer and detect it.
	bd := NewBase64Detector(&talismanrc.TalismanRC{})
	assert.NotEmpty(t, bd.CheckBase64Encoding(base64AndHexEncoded))

	messages := scanNestedDecodingTestContent(t, base64AndHexEncoded)
	if len(messages) == 0 {
		t.Fatal("expected nested base64(hex(secret)) to be detected")
	}
	report := strings.Join(messages, " ")
	assert.Contains(t, report, base64AndHexEncoded[:20])
	assert.NotContains(t, report, secret[:20])
	assert.NotContains(t, report, hexEncoded[:20])
}

func TestFixedControlAndNestedSecretStaySeparated(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	base64AndHexEncoded := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte(secret))))
	content := nestedDecodeBoundaryControl + "\n" + base64AndHexEncoded

	messages := scanNestedDecodingTestContent(t, content)
	if len(messages) == 0 {
		t.Fatal("expected the nested secret next to the fixed control to be detected")
	}
	report := strings.Join(messages, " ")
	assert.Contains(t, report, base64AndHexEncoded[:20])
	assert.NotContains(t, report, nestedDecodeBoundaryControl[:20])
	assert.NotContains(t, report, secret[:20])
}

func TestLineWrappedNestedEncodingIsDetectedWithoutLeakingDecodedValue(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	hexEncoded := hex.EncodeToString([]byte(secret))
	base64AndHexEncoded := base64.StdEncoding.EncodeToString([]byte(hexEncoded))

	var wrapped strings.Builder
	for index := 0; index < len(base64AndHexEncoded); index += 20 {
		end := index + 20
		if end > len(base64AndHexEncoded) {
			end = len(base64AndHexEncoded)
		}
		wrapped.WriteString(base64AndHexEncoded[index:end])
		wrapped.WriteString("\n")
	}

	messages := scanNestedDecodingTestContent(t, wrapped.String())
	if len(messages) == 0 {
		t.Fatal("expected line-wrapped nested encoding to be detected")
	}
	report := strings.Join(messages, " ")
	assert.NotContains(t, report, secret[:20])
	assert.NotContains(t, report, hexEncoded[:20])
}

func TestDecodersAcceptLegalWhitespaceAndPadding(t *testing.T) {
	padded := base64.StdEncoding.EncodeToString([]byte("hello world"))
	decoded, ok := decodeBase64String(padded[:4] + "\r\n" + padded[4:])
	assert.True(t, ok)
	assert.Equal(t, "hello world", decoded)

	unpadded := base64.RawStdEncoding.EncodeToString([]byte("hello world!"))
	decoded, ok = decodeBase64String(unpadded[:5] + "\n " + unpadded[5:])
	assert.True(t, ok)
	assert.Equal(t, "hello world!", decoded)

	hexEncoded := hex.EncodeToString([]byte("hello world"))
	decoded, ok = decodeHexString(hexEncoded[:6] + "\n" + hexEncoded[6:])
	assert.True(t, ok)
	assert.Equal(t, "hello world", decoded)
}

func TestOversizedDecodedValueFailsClosed(t *testing.T) {
	// The decoded value is larger than the supplied expansion budget. The
	// fragment must be treated as suspicious (fail closed) rather than
	// silently skipped.
	encoded := base64.StdEncoding.EncodeToString([]byte("this value is larger than the remaining budget"))
	decoder := newNestedDecodingTestDecoder()
	assert.Equal(t, nestedFailClosed, decoder.inspect(encoded, 0, base64Content, 4))
}

func TestCyclesAndExcessiveDepthFailClosed(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("cycle"))

	cycleDecoder := newNestedDecodingTestDecoder()
	digest := sha256.Sum256([]byte(encoded))
	cycleDecoder.seen[digest] = true
	assert.Equal(t, nestedFailClosed, cycleDecoder.inspect(encoded, 0, base64Content, maxNestedExpandedBytes))

	depthDecoder := newNestedDecodingTestDecoder()
	assert.Equal(t, nestedFailClosed, depthDecoder.inspect(encoded, maxNestedDecodeDepth, base64Content, maxNestedExpandedBytes))
}

func newNestedDecodingTestDecoder() *nestedDecoder {
	return &nestedDecoder{
		base64Threshold: BASE64_ENTROPY_THRESHOLD,
		entropy:         &Entropy{},
		wordCheck:       &WordCheck{},
		seen:            map[[sha256.Size]byte]bool{},
	}
}
