package redisdriver

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"github.com/termermc/go-capjs/cap"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// DefaultKeyPrefix is the default Redis key prefix to use.
const DefaultKeyPrefix = "cap:"

type Driver struct {
	client redis.UniversalClient

	logger    *slog.Logger
	rlOpts    *cap.RateLimitOptions
	keyPrefix string
}

// WithLogger sets the logger.
// When not specified, uses slog.Default.
func WithLogger(logger *slog.Logger) func(d *Driver) {
	return func(d *Driver) {
		d.logger = logger
	}
}

// WithRateLimit enables rate limiting and uses the specified options for it.
func WithRateLimit(opts ...func(rl *cap.RateLimitOptions)) func(d *Driver) {
	return func(d *Driver) {
		rl := cap.NewDefaultRateLimitOptions()

		for _, opt := range opts {
			opt(rl)
		}

		d.rlOpts = rl
	}
}

// WithKeyPrefix sets the Redis key prefix to use.
// When not specified, uses DefaultKeyPrefix.
func WithKeyPrefix(prefix string) func(d *Driver) {
	return func(d *Driver) {
		d.keyPrefix = prefix
	}
}

// NewDriver creates a new Redis driver with the specified Redis connection options.
func NewDriver(clientOpts ToRedisClient, opts ...func(d *Driver)) (*Driver, error) {
	client := clientOpts.ToClient()

	err := client.Ping(context.Background()).Err()
	if err != nil {
		return nil, fmt.Errorf(`redisdriver: failed to connect to Redis: %w`, err)
	}

	d := &Driver{
		client: client,

		logger:    slog.Default(),
		rlOpts:    nil,
		keyPrefix: DefaultKeyPrefix,
	}

	for _, opt := range opts {
		opt(d)
	}

	return d, nil
}

func (d *Driver) Close() error {
	return d.client.Close()
}

func (d *Driver) Store(ctx context.Context, challenge *cap.Challenge, ip *netip.Addr) error {
	if ip != nil && d.rlOpts != nil {
		// Rate limit.
		rl := d.rlOpts

		ipVer, ipInt := cap.IpToInt64(ip, rl.IPv4SignificantBits, rl.IPv6SignificantBits)

		key := d.keyPrefix + "limit:" + strconv.Itoa(ipVer) + cap.Int64ToHex(ipInt)

		res, err := d.client.Incr(ctx, key).Result()
		if err != nil {
			return fmt.Errorf(`redisdriver: failed to increment rate limit key: %w`, err)
		}

		if res == 1 {
			// New key, set TTL.
			err = d.client.Expire(ctx, key, rl.MaxChallengesWindow).Err()
			if err != nil {
				return fmt.Errorf(`redisdriver: failed to set rate limit key expiration: %w`, err)
			}
		}

		if res > int64(rl.MaxChallengesPerIP) {
			return cap.ErrRateLimited
		}
	}

	// Encode challenge.
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(challenge)
	if err != nil {
		return fmt.Errorf(`redisdriver: failed to encode challenge: %w`, err)
	}

	chalKey := d.keyPrefix + "challenge:" + challenge.ChallengeToken
	redeemKey := d.keyPrefix + "redeem:" + challenge.RedeemToken

	expDur := time.Now().Sub(challenge.Expires)

	// Set challenge and redeem token pointer to challenge.
	_, err = d.client.TxPipelined(ctx, func(pipeline redis.Pipeliner) error {
		err = d.client.Set(ctx, chalKey, buf.Bytes(), expDur).Err()
		if err != nil {
			return err
		}
		err = d.client.Set(ctx, redeemKey, challenge.ChallengeToken, expDur).Err()
		if err != nil {
			return nil
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf(`redisdriver: failed to save challenge to Redis: %w`, err)
	}

	return nil
}

func (d *Driver) GetUnredeemedChallenge(ctx context.Context, challengeToken string) (*cap.Challenge, error) {
	// Get challenge.
	// We don't need to worry about checking whether it's expired or redeemed because it will be deleted in either of those cases.
	key := d.keyPrefix + "challenge:" + challengeToken
	res, err := d.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Nonexistent, redeemed or expired challenge.
			return nil, nil
		}

		return nil, fmt.Errorf(`redisdriver: failed to get challenge with token "%s": %w`, challengeToken, err)
	}

	// Decode challenge.
	var chal cap.Challenge
	dec := gob.NewDecoder(strings.NewReader(res))
	err = dec.Decode(&chal)
	if err != nil {
		return nil, fmt.Errorf(`redisdriver: failed to decode challenge data for token "%s": %w`, challengeToken, err)
	}

	return &chal, nil
}

func (d *Driver) UseRedeemToken(ctx context.Context, redeemToken string) (wasRedeemed bool, err error) {
	redeemKey := d.keyPrefix + "redeem:" + redeemToken
	chalToken, err := d.client.GetDel(ctx, redeemKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}

		return false, fmt.Errorf(`redisdriver: failed to getdel Redis entry for redeem token "%s": %w`, redeemToken, err)
	}

	chalKey := d.keyPrefix + "challenge:" + chalToken
	delCount, err := d.client.Del(ctx, chalKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}

		return false, fmt.Errorf(`redisdriver: failed to delete challenge token "%s" key in Redis: %w`, chalToken, err)
	}

	return delCount > 0, nil
}
