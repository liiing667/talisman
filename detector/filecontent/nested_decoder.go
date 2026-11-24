package filecontent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// Nested encoding support is deliberately bounded. Secrets are frequently
// wrapped more than once (for example base64 around hex) and are also wrapped
// at fixed line widths. Decoding those layers is useful, but an attacker must
// not be able to make the scanner recurse forever, allocate an unbounded
// amount of memory, or leak the decoded value into the findings report.
const (
	// maxNestedDecodeDepth is the number of decode layers that may be peeled
	// from a single encoded fragment. Anything deeper is treated as hostile.
	maxNestedDecodeDepth = 8

	// maxNestedExpandedBytes bounds the total amount of decoded data produced
	// while peeling one fragment. It protects against oversized encoded input
	// and against decoding "bombs" that would otherwise consume all memory.
	maxNestedExpandedBytes = 1 << 20 // 1 MiB

	// maxNestedEncodedBytes bounds the size of an individual encoded layer
	// that we are willing to hand to a decoder.
	maxNestedEncodedBytes = 8 << 20 // 8 MiB

	// maxNestedExpansionFactor catches decoders that grow text unexpectedly
	// (for example a future decoder that expands its input). Base64 and hex
	// both shrink during decoding, so this is a defensive backstop.
	maxNestedExpansionFactor = 64

	// maxNestedDecodeNodes bounds combinatorial branching when a layer is
	// ambiguously valid as more than one encoding.
	maxNestedDecodeNodes = 4096

	minNestedEncodedLength = 8
)

const contentHintAny contentType = contentType(-1)

type nestedDecodeOutcome int

const (
	nestedNothing nestedDecodeOutcome = iota
	nestedSecret
	nestedFailClosed
)

type nestedDecoder struct {
	base64Threshold float64
	entropy         *Entropy
	wordCheck       *WordCheck
	seen            map[[sha256.Size]byte]bool
	nodes           int
	limitHit        bool
}

type nestedDecodedLayer struct {
	text string
}

// detectNestedSecret reports whether text contains a secret either directly in
// one of its decoded layers or through an encoding chain that hit one of the
// safety limits. In both cases the caller reports the original encoded text,
// never the decoded value.
func detectNestedSecret(text string, hint contentType, base64Threshold float64) bool {
	if base64Threshold <= 0 {
		base64Threshold = BASE64_ENTROPY_THRESHOLD
	}
	decoder := &nestedDecoder{
		base64Threshold: base64Threshold,
		entropy:         &Entropy{},
		wordCheck:       &WordCheck{},
		seen:            map[[sha256.Size]byte]bool{},
	}
	return decoder.inspect(text, 0, hint, maxNestedExpandedBytes) != nestedNothing
}

func (d *nestedDecoder) inspect(text string, depth int, hint contentType, budget int) nestedDecodeOutcome {
	if text == "" {
		return nestedNothing
	}

	// The caller has already run its normal single-layer detector at depth 0.
	// Only decoded layers are checked for newly exposed high-entropy content.
	if depth > 0 && d.layerContainsSecret(text) {
		return nestedSecret
	}

	digest := sha256.Sum256([]byte(text))
	if d.seen[digest] {
		return nestedFailClosed
	}

	if depth >= maxNestedDecodeDepth {
		if len(d.decodedLayers(text, depth, hint)) > 0 || d.limitHit {
			return nestedFailClosed
		}
		return nestedNothing
	}

	d.seen[digest] = true
	defer delete(d.seen, digest)

	layers := d.decodedLayers(text, depth, hint)
	if d.limitHit {
		return nestedFailClosed
	}
	for _, layer := range layers {
		if len(layer.text) > budget {
			return nestedFailClosed
		}
		if !isNestedText(layer.text) {
			continue
		}
		if len(layer.text) > len(text)*maxNestedExpansionFactor+maxNestedExpandedBytes {
			return nestedFailClosed
		}
		if outcome := d.inspect(layer.text, depth+1, contentHintAny, budget-len(layer.text)); outcome != nestedNothing {
			return outcome
		}
	}
	return nestedNothing
}

func (d *nestedDecoder) decodedLayers(text string, depth int, hint contentType) []nestedDecodedLayer {
	d.nodes++
	if d.nodes > maxNestedDecodeNodes {
		d.limitHit = true
		return nil
	}

	layers := []nestedDecodedLayer{}
	seen := map[string]bool{}
	add := func(decoded string, ok bool) {
		if !ok || decoded == "" || seen[decoded] {
			return
		}
		if len(text) > 0 && len(decoded) > len(text)*maxNestedExpansionFactor+maxNestedExpandedBytes {
			d.limitHit = true
			return
		}
		seen[decoded] = true
		layers = append(layers, nestedDecodedLayer{text: decoded})
	}

	// Whitespace is legal inside base64/hex blobs (MIME wrapping, formatted
	// configuration). Try the whole value first so wrapped values decode.
	condensed := stripEncodingWhitespace(text)
	if len(condensed) > maxNestedEncodedBytes && (isBase64Alphabet(condensed) || isHexAlphabet(condensed)) {
		d.limitHit = true
		return nil
	}
	if depth == 0 {
		switch hint {
		case base64Content:
			if len(condensed) >= MIN_BASE64_SECRET_LENGTH {
				add(decodeBase64String(condensed))
			}
			if len(layers) == 0 {
				for _, candidate := range base64Candidates(text) {
					if candidate == condensed || len(candidate) < MIN_BASE64_SECRET_LENGTH {
						continue
					}
					if len(candidate) > maxNestedEncodedBytes {
						d.limitHit = true
						continue
					}
					add(decodeBase64String(candidate))
				}
			}
		case hexContent:
			if len(condensed) >= MIN_HEX_SECRET_LENGTH {
				add(decodeHexString(condensed))
			}
			if len(layers) == 0 {
				for _, candidate := range hexCandidates(text) {
					if candidate == condensed || len(candidate) < MIN_HEX_SECRET_LENGTH {
						continue
					}
					if len(candidate) > maxNestedEncodedBytes {
						d.limitHit = true
						continue
					}
					add(decodeHexString(candidate))
				}
			}
		}
		return layers
	}

	// Once inside a decoded layer, either encoding may be the next one in the
	// chain. Whole-value decoding is attempted first because the layer is
	// usually just the encoded payload with optional whitespace.
	add(decodeBase64String(condensed))
	add(decodeHexString(condensed))
	for _, candidate := range base64Candidates(text) {
		if candidate == condensed {
			continue
		}
		if len(candidate) > maxNestedEncodedBytes {
			d.limitHit = true
			continue
		}
		add(decodeBase64String(candidate))
	}
	for _, candidate := range hexCandidates(text) {
		if candidate == condensed {
			continue
		}
		if len(candidate) > maxNestedEncodedBytes {
			d.limitHit = true
			continue
		}
		add(decodeHexString(candidate))
	}
	return layers
}

func (d *nestedDecoder) layerContainsSecret(text string) bool {
	if d.textContainsSecret(text) {
		return true
	}

	// A decoded layer may itself be line-wrapped. Only collapse whitespace
	// when the result is a pure encoded value; doing this unconditionally
	// would join unrelated prose into artificial high-entropy candidates.
	condensed := stripEncodingWhitespace(text)
	if condensed != text && (isBase64Alphabet(condensed) || isHexAlphabet(condensed)) {
		return d.textContainsSecret(condensed)
	}
	return false
}

func (d *nestedDecoder) textContainsSecret(text string) bool {
	for _, candidate := range base64Candidates(text) {
		if len(candidate) <= MIN_BASE64_SECRET_LENGTH {
			continue
		}
		entropy := d.entropy.GetShannonEntropy(candidate, BASE64_CHARS)
		if entropy > d.base64Threshold && !d.wordCheck.containsWordsOnly(candidate) {
			return true
		}
	}
	for _, candidate := range hexCandidates(text) {
		if len(candidate) <= MIN_HEX_SECRET_LENGTH {
			continue
		}
		if d.entropy.GetShannonEntropy(candidate, HEX_CHARS) > HEX_ENTROPY_THRESHOLD {
			return true
		}
	}
	return false
}

func stripEncodingWhitespace(text string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			return -1
		}
		return r
	}, text)
}

func decodeBase64String(text string) (string, bool) {
	encoded := stripEncodingWhitespace(text)
	if len(encoded) < minNestedEncodedLength || len(encoded) > maxNestedEncodedBytes {
		return "", false
	}
	if !isBase64Alphabet(encoded) {
		return "", false
	}

	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		decoded, err := encoding.DecodeString(encoded)
		if err == nil && len(decoded) > 0 {
			return string(decoded), true
		}
	}
	return "", false
}

func decodeHexString(text string) (string, bool) {
	encoded := stripEncodingWhitespace(text)
	if len(encoded) < minNestedEncodedLength || len(encoded) > maxNestedEncodedBytes || len(encoded)%2 != 0 {
		return "", false
	}
	if !isHexAlphabet(encoded) {
		return "", false
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) == 0 {
		return "", false
	}
	return string(decoded), true
}

func isNestedText(text string) bool {
	if text == "" || !utf8.ValidString(text) {
		return false
	}
	printable := 0
	total := 0
	for _, r := range text {
		total++
		if r == '\r' || r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			printable++
		}
	}
	return total > 0 && float64(printable)/float64(total) >= 0.95
}

func base64Candidates(text string) []string {
	candidates := []string{}
	var current strings.Builder
	flush := func() {
		if current.Len() == 0 {
			return
		}
		run := current.String()
		current.Reset()
		candidates = append(candidates, run)
		if strings.IndexByte(run, '=') < 0 {
			return
		}
		// "key=value" is common in configuration files. The run scanner sees
		// it as one base64-ish token, so also try the parts around '='.
		for _, part := range strings.Split(run, "=") {
			if part != "" && part != run {
				candidates = append(candidates, part)
			}
		}
	}

	for i := 0; i < len(text); i++ {
		c := text[i]
		if isBase64Char(c) || c == '=' {
			current.WriteByte(c)
			continue
		}
		flush()
	}
	flush()
	return candidates
}

func hexCandidates(text string) []string {
	candidates := []string{}
	start := -1
	for i := 0; i < len(text); i++ {
		if isHexChar(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			candidates = append(candidates, text[start:i])
			start = -1
		}
	}
	if start >= 0 {
		candidates = append(candidates, text[start:])
	}
	return candidates
}

func isBase64Char(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '+' || c == '/'
}

func isHexChar(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

func isBase64Alphabet(text string) bool {
	if text == "" {
		return false
	}
	padding := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '=' {
			padding++
			if padding > 2 {
				return false
			}
			continue
		}
		if padding > 0 || !isBase64Char(c) {
			return false
		}
	}
	return true
}

func isHexAlphabet(text string) bool {
	if text == "" {
		return false
	}
	for i := 0; i < len(text); i++ {
		if !isHexChar(text[i]) {
			return false
		}
	}
	return true
}
