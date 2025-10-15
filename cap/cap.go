package cap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Cap is an implementation of the Cap server.
// It can create challenges, accept solutions, and redeem tokens.
// It uses a driver for storing challenges (and optional rate limiting).
type Cap struct {
	driver Driver
}

// NewCap creates a new Cap instance with the specified driver.
func NewCap(driver Driver) *Cap {
	s := &Cap{
		driver: driver,
	}

	return s
}

// Challenge is a Cap challenge.
// It includes a challenge token, used to identify the challenge,
// a redeem token, which will be returned to clients who successfully solve the challenge,
// and params which are used to verify the challenge solution.
// The expiration time is the cutoff point where the challenge can no longer be solved, and
// its redeem token can no longer be redeemed.
type Challenge struct {
	// The token used to identify the challenge.
	ChallengeToken string

	// The redeem token, returned for correct solutions.
	// This can be redeemed once by a client once received.
	RedeemToken string

	// The parameters used to generate the challenge and verify its solution.
	Params ChallengeParams

	// The expiration time, when solutions will no longer be accepted and the redeem token
	// will no longer be accepted.
	Expires time.Time
}

// ToResponse returns a ChallengeResponse with the data inside the Challenge struct.
func (c *Challenge) ToResponse() ChallengeResponse {
	return ChallengeResponse{
		Params:        c.Params,
		ChallengeHash: c.ChallengeToken,
		ExpiresMs:     c.Expires.UnixMilli(),
	}
}

// ChallengeParams are the parameters for creating and validating a challenge.
// This struct can be serialized into a valid JSON challenge response.
type ChallengeParams struct {
	// The difficulty level of the challenge.
	Difficulty int `json:"d"`

	// The number of challenges to generate.
	Count int `json:"c"`

	// The size of the salt in bytes.
	SaltSize int `json:"s"`
}

// ChallengeRequest is a request to create a challenge
type ChallengeRequest struct {
	// The parameters for the challenge.
	Params ChallengeParams

	// The IP address that is requesting the challenge.
	// Can be nil.
	// Used by the driver for optional rate limiting.
	IP *netip.Addr

	// The duration for which the challenge is valid.
	ValidDuration time.Duration
}

// DefaultChallengeParams are the default parameters to use for challenges.
var DefaultChallengeParams = ChallengeParams{
	Difficulty: 4,
	Count:      50,
	SaltSize:   32,
}

// DefaultValidDuration is the default duration that a Cap challenge is valid before it expires.
const DefaultValidDuration = 10 * time.Minute

// ChallengeResponse is a challenge response that can be sent to a client that requested one.
// It can be serialized to JSON and used as the JSON response for the challenge endpoint.
type ChallengeResponse struct {
	// The challenge parameters.
	Params ChallengeParams `json:"challenge"`

	// The challenge hash/token.
	ChallengeHash string `json:"token"`

	// The UNIX millisecond timestamp when the challenge expires.
	ExpiresMs int64 `json:"expires"`
}

// CreateChallenge generates a new challenge.
// If the request IP is set and the driver has rate limiting enabled, the function may return ErrRateLimited.
func (s *Cap) CreateChallenge(ctx context.Context, req ChallengeRequest) (*Challenge, error) {
	// Generate a random challenge and redeem tokens
	randBytes := make([]byte, 25)
	_, _ = rand.Read(randBytes)
	challengeToken := hex.EncodeToString(randBytes)
	_, _ = rand.Read(randBytes)
	redeemToken := hex.EncodeToString(randBytes)

	expires := time.Now().Add(req.ValidDuration)

	challenge := &Challenge{
		ChallengeToken: challengeToken,
		RedeemToken:    redeemToken,
		Params:         req.Params,
		Expires:        expires,
	}

	err := s.driver.Store(ctx, challenge, req.IP)
	if err != nil {
		return nil, err
	}

	return challenge, nil
}

// VerifySolutionsRequest is the request for verifying a challenge solution.
// It can be used to deserialize a JSON request body.
type VerifySolutionsRequest struct {
	ChallengeToken string   `json:"token"`
	Solutions      []uint32 `json:"solutions"`
}

// RedeemData is the redemption data returned after verifying a successful solution.
type RedeemData struct {
	RedeemToken string
	Expires     time.Time
}

// ErrChallengeNotFound is returned when a challenge is not found, expired, or already redeemed.
var ErrChallengeNotFound = errors.New("challenge not found (or is expired or already redeemed)")

// ErrInsufficientSolutions is returned when not enough solutions were provided for a challenge.
var ErrInsufficientSolutions = errors.New("insufficient solutions provided for challenge")

// ErrInvalidSolution is returned when a solution is invalid.
var ErrInvalidSolution = errors.New("invalid solution provided for challenge")

// VerifyChallengeSolutions verifies a challenge's solution in exchange for a redeem token.
// Returns ErrChallengeNotFound if no challenge with the specified token exists.
// Returns ErrInsufficientSolutions if not enough solutions were provided.
// Returns ErrInvalidSolution if any solution is invalid.
func (s *Cap) VerifyChallengeSolutions(ctx context.Context, req VerifySolutionsRequest) (*RedeemData, error) {
	src, err := s.driver.GetUnredeemedChallenge(ctx, req.ChallengeToken)
	if err != nil {
		return nil, err
	}

	if src == nil {
		return nil, ErrChallengeNotFound
	}

	params := src.Params
	count := params.Count
	if len(req.Solutions) < count {
		return nil, ErrInsufficientSolutions
	}

	token := src.ChallengeToken

	type challengeTuple struct {
		Salt   string
		Target string
	}
	challenges := make([]challengeTuple, count)
	for i := 0; i < count; i++ {
		idx := i + 1
		challenges[i] = challengeTuple{
			Salt:   prng(fmt.Sprintf("%s%d", token, idx), params.SaltSize),
			Target: prng(fmt.Sprintf("%s%dd", token, idx), params.Difficulty),
		}
	}

	isValid := true
	for i, challenge := range challenges {
		// We checked that the number of solutions is equal to the number of challenges earlier, so this can't panic.
		solution := req.Solutions[i]

		salt := challenge.Salt
		target := challenge.Target
		hasher := sha256.New()
		hasher.Write([]byte(salt))
		hasher.Write([]byte(strconv.FormatInt(int64(solution), 10)))
		hash := hex.EncodeToString(hasher.Sum(nil))

		if !strings.HasPrefix(hash, target) {
			isValid = false
			break
		}
	}

	// Check if solution is valid.
	if !isValid {
		return nil, ErrInvalidSolution
	}

	return &RedeemData{
		RedeemToken: src.RedeemToken,
		Expires:     src.Expires,
	}, nil
}

// UseRedeemToken uses up a redeem token and returns whether it was valid, invalidating it either way.
func (s *Cap) UseRedeemToken(ctx context.Context, token string) (bool, error) {
	return s.driver.UseRedeemToken(ctx, token)
}
