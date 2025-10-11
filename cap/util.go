package cap

import (
	"fmt"
	"strings"
	"unicode/utf16"
)

// fnv1a implements the FNV-1a hash algorithm.
func fnv1a(str string) uint32 {
	var hash uint32 = 2166136261
	// Convert string to runes, then to UTF-16 code units
	runes := []rune(str)
	utf16s := utf16.Encode(runes)
	for _, codeUnit := range utf16s {
		hash ^= uint32(codeUnit)
		hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24)
	}
	return hash
}

// prng generates a deterministic hex string of given length from a string seed.
// `seed` is the initial seed value.
// `length` is the output hex string length.
func prng(seed string, length int) string {
	state := fnv1a(seed)
	var result strings.Builder

	next := func() uint32 {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		return state
	}

	for result.Len() < length {
		rnd := next()
		// Format as 8-digit hex, pad with zeros if needed
		result.WriteString(fmt.Sprintf("%08x", rnd))
	}

	return result.String()[:length]
}
