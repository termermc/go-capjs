package cap

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// ErrRateLimited is returned when a rate limit for an IP has been reached.
// This can be returned by Driver.Store when an IP address is specified.
// Rate limits are defined by driver implementations.
var ErrRateLimited = errors.New("captcha could not be created because a rate limit was hit")

// Driver is a driver for managing Cap challenges.
// A driver is responsible for storing, updating and retrieving challenges.
// It is also responsible for clearing expired challenges, and optionally
// enforcing rate limits.
type Driver interface {
	// Store stores a challenge.
	// The challenge must not be nil.
	// The driver is responsible for clearing expired challenges.
	//
	// If `ip` is not nil, it can be used for rate limiting, and the
	// driver may return ErrRateLimited.
	Store(ctx context.Context, challenge *Challenge, ip *netip.Addr) error

	// GetUnredeemedChallenge returns the unredeemed challenge with the specified challenge token.
	// Returns nil if the challenge does not exist, is expired, or is already redeemed.
	//
	// Will not return ErrRateLimited.
	GetUnredeemedChallenge(ctx context.Context, challengeToken string) (*Challenge, error)

	// UseRedeemToken redeems the specified redeem token.
	// If the challenge did not exist, was expired, or was already redeemed, returns false.
	// If the redemption was successful, returns true.
	// The redeem token must not be able to be re-used after calling this function with it.
	//
	// Will not return ErrRateLimited.
	UseRedeemToken(ctx context.Context, redeemToken string) (wasRedeemed bool, err error)
}

const DefaultIPv4SignificantBits = 32
const DefaultIPv6SignificantBits = 64

const DefaultMaxChallengesPerIP = 60
const DefaultMaxChallengesWindow = 1 * time.Minute

// RateLimitOptions are options for applying rate limiting to the Cap drivers.
// It limits challenge creation based on IP address.
// The specific rate limit algorithm and implementation is defined by the driver.
// IP addresses are truncated to a specified number of bits. For example, you can limit based
// on the /24 subnet for IPv4 and /48 for IPv6 instead of the default /32 and /64.
type RateLimitOptions struct {
	IPv4SignificantBits int
	IPv6SignificantBits int

	MaxChallengesPerIP  int
	MaxChallengesWindow time.Duration
}

// NewDefaultRateLimitOptions returns a new RateLimitOptions with default values.
func NewDefaultRateLimitOptions() *RateLimitOptions {
	return &RateLimitOptions{
		IPv4SignificantBits: DefaultIPv4SignificantBits,
		IPv6SignificantBits: DefaultIPv6SignificantBits,
		MaxChallengesPerIP:  DefaultMaxChallengesPerIP,
		MaxChallengesWindow: DefaultMaxChallengesWindow,
	}
}

// WithIPv4SignificantBits sets the significant bits (netmask) to use for rate limit counting on IPv4 addresses.
// When not specified, uses DefaultIPv4SignificantBits.
func WithIPv4SignificantBits(bits int) func(rl *RateLimitOptions) {
	return func(rl *RateLimitOptions) {
		rl.IPv4SignificantBits = bits
	}
}

// WithIPv6SignificantBits sets the significant bits (netmask) to use for rate limit counting on IPv6 addresses.
// When not specified, uses DefaultIPv6SignificantBits.
func WithIPv6SignificantBits(bits int) func(rl *RateLimitOptions) {
	return func(rl *RateLimitOptions) {
		rl.IPv6SignificantBits = bits
	}
}

// WithMaxChallengesPerIP sets the maximum allowed challenges that can be generated per IP.
// The underlying window algorithm (e.g. sliding window, fixed window, etc.) is determined by the specific driver.
// When not specified, uses DefaultMaxChallengesPerIP.
func WithMaxChallengesPerIP(max int) func(rl *RateLimitOptions) {
	return func(rl *RateLimitOptions) {
		rl.MaxChallengesPerIP = max
	}
}

// WithMaxChallengesWindow sets the window of time in which challenge creations are counted.
// The underlying window algorithm (e.g. sliding window, fixed window, etc.) is determined by the specific driver.
// When not specified, uses DefaultMaxChallengesWindow.
func WithMaxChallengesWindow(window time.Duration) func(rl *RateLimitOptions) {
	return func(rl *RateLimitOptions) {
		rl.MaxChallengesWindow = window
	}
}
