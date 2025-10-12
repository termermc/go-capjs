package sqlitedriver

import (
	"context"
	"database/sql"
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

type Driver struct {
	sqlite *sql.DB
	opts   DriverOptions
	rlOpts *RateLimitOptions

	delExpiredStmt *sql.Stmt

	isClosed bool
}

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

	go d.delExpiredDaemon()
	// TODO Daemon, also Close method for ending daemon and closing prepared statements

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

func (d *Driver) Store(ctx context.Context, challenge *cap.Challenge, ip *netip.Addr) error {
	return nil
}

func (d *Driver) GetUnredeemedChallenge(ctx context.Context, challengeToken string) (*cap.Challenge, error) {
	return nil, nil
}

func (d *Driver) UseRedeemToken(ctx context.Context, redeemToken string) (wasRedeemed bool, err error) {
	return false, nil
}
