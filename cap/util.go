package cap

import (
	"encoding/binary"
	"fmt"
	"net/netip"
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

// IpToInt64 converts an IP address to an integer, containing the significant bits specified.
// The ipV4SignificantBits parameter must be between 0 and 32 (inclusive),
// and the ipV6SignificantBits parameter must be between 0 and 64 (inclusive).
// IPv6 significant bits are capped to 64 instead of 128 because properly configured IPv6 networks
// tend not to provide smaller than /64 blocks. We also want to be able to store the IP in a 64 bit
// integer.
//
// If the significant bits parameters are out of bounds, this function panics.
func IpToInt64(addr netip.Addr, ipVSignificantBits int, ipV6SignificantBits int) (version int, integer int64) {
	if addr.Is6() {
		byteCount := ipV6SignificantBits / 8
		if byteCount > 64 {

		}

		var beBytes [8]byte
		for i, b := range addr.As16() {
			if i >= byteCount {
				break
			}

			beBytes[i] = b
		}

		version = 6
		integer = int64(binary.BigEndian.Uint64(beBytes[:]))
	} else {
		byteCount := ipVSignificantBits / 8
		var beBytes [8]byte
		for i, b := range addr.As4() {
			if i >= byteCount {
				break
			}

			beBytes[i+4] = b
		}

		version = 4
		integer = int64(binary.BigEndian.Uint64(beBytes[:]))
	}

	return
}
