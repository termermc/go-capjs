package cap

import (
	"context"
	"errors"
	"net/netip"
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
