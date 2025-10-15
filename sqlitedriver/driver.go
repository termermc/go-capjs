package sqlitedriver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/termermc/go-capjs/cap"
	"github.com/termermc/go-capjs/sqlitedriver/migration"
)

const DefaultExpiredSessionPruneInterval = 1 * time.Minute

const DefaultIPv4SignificantBits = 32
const DefaultIPv6SignificantBits = 64

// RateLimitOptions are options for applying rate limiting to the Cap SQLite driver.
// If enabled, it uses a sliding window algorithm to limit challenge creation by IP address.
// IP addresses are truncated to a specified number of bits. For example, you can limit based
// on the /24 subnet for IPv4 and /48 for IPv6 instead of the default /32 and /64.
type RateLimitOptions struct {
	// The significant bits to use for counting challenges by IPv4 address.
	// Must be at maximum /32. Higher values will be clamped to /32.
	// If omitted/zero, defaults to DefaultIPv4SignificantBits.
	IPv4SignificantBits int

	// The significant bits to use for counting challenges by IPv6 address.
	// Must be at maximum /64. Higher values will be clamped to /64.
	// If omitted/zero, defaults to DefaultIPv6SignificantBits.
	//
	// A maximum of /64 is allowed instead of /128 because properly configured
	// IPv6 networks issue /64 blocks, and it is a more reliable way to limit.
	// Allowing smaller subnets would open up the system to abuse.
	IPv6SignificantBits int

	// The maximum number of challenges to allow per IP within the window defined by MaxChallengesWindow.
	// If 0, there is no limit.
	MaxChallengesPerIp int

	// The window in which to count challenges by IP.
	// Precision is seconds.
	// Uses a sliding window algorithm.
	MaxChallengesWindow time.Duration
}

// DriverOptions are options for the Cap SQLite driver.
type DriverOptions struct {
	// The logger to use.
	// If unspecified, uses slog.Default.
	Logger *slog.Logger

	// The interval at which to prune expired sessions from the database.
	// If unspecified/zero, defaults to DefaultExpiredSessionPruneInterval.
	ExpiredSessionPruneInterval time.Duration

	// The rate limiting options to apply, if any.
	// If nil, rate limiting will be disabled.
	RateLimitOpts *RateLimitOptions
}

// Driver is the SQLite driver for Cap.
// It stores challenges in an SQLite database, and optionally uses it for rate limiting.
//
// Note that the DB used to create the Driver will be closed when Driver.Close is called.
// The DB should be in WAL mode for ideal performance.
type Driver struct {
	sqlite *sql.DB
	opts   DriverOptions
	rlOpts *RateLimitOptions

	delExpiredStmt     *sql.Stmt
	insertStmt         *sql.Stmt
	getIpCountStmt     *sql.Stmt
	getUnredeemedStmt  *sql.Stmt
	useRedeemTokenStmt *sql.Stmt

	isClosed bool
}

// NewDriver creates a new SQLite driver with the specified DB and options.
// Note that the DB passed in will be closed when Driver.Close is called.
func NewDriver(sqlite *sql.DB, opts DriverOptions) (*Driver, error) {
	d := &Driver{
		sqlite: sqlite,
		opts:   opts,
	}

	if d.opts.Logger == nil {
		d.opts.Logger = slog.Default()
	}

	if d.opts.ExpiredSessionPruneInterval == 0 {
		d.opts.ExpiredSessionPruneInterval = DefaultExpiredSessionPruneInterval
	}

	var rlOpts RateLimitOptions
	if opts.RateLimitOpts != nil {
		rlOpts = *opts.RateLimitOpts

		if rlOpts.IPv4SignificantBits < 1 {
			rlOpts.IPv4SignificantBits = DefaultIPv4SignificantBits
		} else if rlOpts.IPv4SignificantBits > 32 {
			rlOpts.IPv4SignificantBits = 32
		}

		if rlOpts.IPv6SignificantBits < 1 {
			rlOpts.IPv6SignificantBits = DefaultIPv6SignificantBits
		} else if rlOpts.IPv6SignificantBits > 64 {
			rlOpts.IPv6SignificantBits = 64
		}

		opts.RateLimitOpts = &rlOpts
	}

	if err := migration.DoMigrations(sqlite); err != nil {
		return nil, err
	}

	stmt, err := sqlite.Prepare("delete from cap_challenge where expires_ts < ?")
	if err != nil {
		return nil, err
	}
	d.delExpiredStmt = stmt

	stmt, err = sqlite.Prepare(`
		insert into cap_challenge (
		    challenge_token,
		    redeem_token,
		    challenge_difficulty,
		    challenge_count,
		    challenge_salt_size,
		    ip_version,
		    ip_significant_bits,
		    expires_ts,
		) values (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, err
	}
	d.insertStmt = stmt

	stmt, err = sqlite.Prepare("select count(*) from cap_challenge where ip_version = ? and ip_significant_bits = ? and expires_ts > ?")
	if err != nil {
		return nil, err
	}
	d.getIpCountStmt = stmt

	stmt, err = sqlite.Prepare(`
		select
		    redeem_token,
		    challenge_difficulty,
		    challenge_count,
		    challenge_salt_size,
		    expires_ts
		where
			challenge_token = ? and
			is_redeemed = 0 and
			expires_ts > ?
	`)
	if err != nil {
		return nil, err
	}
	d.getUnredeemedStmt = stmt

	stmt, err = sqlite.Prepare(`
		update cap_challenge
		set is_redeemed = 1
		where
		    redeem_token = ? and
		    is_redeemed = 0 and
		    expires_ts < ?
	`)
	if err != nil {
		return nil, err
	}
	d.useRedeemTokenStmt = stmt

	go d.delExpiredDaemon()

	return d, nil
}

func (d *Driver) delExpiredDaemon() {
	t := time.NewTicker(d.opts.ExpiredSessionPruneInterval)
	for range t.C {
		if d.isClosed {
			return
		}

		res, err := d.delExpiredStmt.Exec(time.Now().Unix())
		if err != nil {
			d.opts.Logger.Error("failed to delete expired Cap challenges",
				"service", "sqlitedriver.Driver",
				"error", err,
			)
			continue
		}

		count, err := res.RowsAffected()
		if err != nil {
			d.opts.Logger.Error("failed to get number of deleted expired Cap challenges",
				"service", "sqlitedriver.Driver",
				"error", err,
			)
			continue
		}

		d.opts.Logger.Debug("deleted expired Cap challenges",
			"service", "sqlitedriver.Driver",
			"count", count,
		)
	}
}

func (d *Driver) Close() error {
	d.isClosed = true

	errs := make([]error, 0, 5)

	if err := d.delExpiredStmt.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := d.insertStmt.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := d.getIpCountStmt.Close(); err != nil {
		errs = append(errs, err)
	}

	if err := d.sqlite.Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf(`failed to Close SQLite Cap driver: %w`, errors.Join(errs...))
	}

	return nil
}

func (d *Driver) Store(ctx context.Context, challenge *cap.Challenge, ip *netip.Addr) error {
	var ipVerPtr *int
	var ipIntPtr *int64

	// Rate limit if enabled.
	if ip != nil && d.opts.RateLimitOpts != nil {
		rl := d.opts.RateLimitOpts
		ipVer, ipInt := cap.IpToInt64(ip, rl.IPv4SignificantBits, rl.IPv6SignificantBits)
		ipVerPtr = &ipVer
		ipIntPtr = &ipInt
		windowStart := time.Now().Add(-rl.MaxChallengesWindow)

		row := d.getIpCountStmt.QueryRowContext(ctx, ipVer, ipInt, windowStart.Unix())

		var count int
		if err := row.Scan(&count); err != nil {
			return fmt.Errorf(`sqlitedriver: failed to get number of Cap challenges by IP %s: %w`, ip.String(), err)
		}

		if count > rl.MaxChallengesPerIp {
			return cap.ErrRateLimited
		}
	}

	p := challenge.Params
	_, err := d.insertStmt.ExecContext(ctx,
		challenge.ChallengeToken,
		challenge.RedeemToken,
		p.Difficulty,
		p.Count,
		p.SaltSize,
		ipVerPtr,
		ipIntPtr,
		challenge.Expires.Unix(),
	)
	if err != nil {
		return fmt.Errorf(`sqlitedriver: failed to insert Cap challenge: %w`, err)
	}

	return nil
}

func (d *Driver) GetUnredeemedChallenge(ctx context.Context, challengeToken string) (*cap.Challenge, error) {
	row := d.getUnredeemedStmt.QueryRowContext(ctx, challengeToken)

	var redeemToken string
	var difficulty int
	var count int
	var saltSize int
	var expTs int64
	if err := row.Scan(&redeemToken, &difficulty, &count, &saltSize, &expTs); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf(`sqlitedriver: failed to get challenge with token "%s": %w`, challengeToken, err)
	}

	return &cap.Challenge{
		ChallengeToken: challengeToken,
		RedeemToken:    redeemToken,
		Params: cap.ChallengeParams{
			Difficulty: difficulty,
			Count:      count,
			SaltSize:   saltSize,
		},
		Expires: time.Unix(expTs, 0),
	}, nil
}

func (d *Driver) UseRedeemToken(ctx context.Context, redeemToken string) (wasRedeemed bool, err error) {
	res, err := d.useRedeemTokenStmt.ExecContext(ctx, redeemToken, time.Now().Unix())
	if err != nil {
		return false, fmt.Errorf(`sqlitedriver: failed to use redeem token "%s": %w`, redeemToken, err)
	}

	var count int64
	count, err = res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf(`sqlitedriver: failed to check if redeem token "%s" was already redeemed: %w`, redeemToken, err)
	}

	return count > 0, nil
}
