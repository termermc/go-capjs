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

const DefaultPruneInterval = 1 * time.Minute

// Driver is the SQLite driver for Cap.
// It stores challenges in an SQLite database, and optionally uses it for rate limiting.
//
// Note that the DB used to create the Driver will be closed when Driver.Close is called.
// The DB should be in WAL mode for ideal performance.
//
// Rate limiting is supported if enabled, and uses a sliding window algorithm.
type Driver struct {
	sqlite *sql.DB

	logger        *slog.Logger
	pruneInterval time.Duration
	rlOpts        *cap.RateLimitOptions

	delExpiredStmt     *sql.Stmt
	insertStmt         *sql.Stmt
	getIPCountStmt     *sql.Stmt
	getUnredeemedStmt  *sql.Stmt
	useRedeemTokenStmt *sql.Stmt

	isClosed bool
}

// WithLogger sets the logger.
// When not specified, uses slog.Default.
func WithLogger(logger *slog.Logger) func(d *Driver) {
	return func(d *Driver) {
		d.logger = logger
	}
}

// WithPruneInterval sets the expired challenge prune interval.
// When not specified, uses DefaultPruneInterval.
func WithPruneInterval(interval time.Duration) func(d *Driver) {
	return func(d *Driver) {
		d.pruneInterval = interval
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

// NewDriver creates a new SQLite driver with the specified DB and options.
// Note that the DB passed in will be closed when Driver.Close is called.
func NewDriver(sqlite *sql.DB, opts ...func(d *Driver)) (*Driver, error) {
	d := &Driver{
		sqlite: sqlite,

		logger:        slog.Default(),
		pruneInterval: DefaultPruneInterval,
		rlOpts:        nil,
	}

	for _, opt := range opts {
		opt(d)
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
		    expires_ts
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
	d.getIPCountStmt = stmt

	stmt, err = sqlite.Prepare(`
		select
		    redeem_token,
		    challenge_difficulty,
		    challenge_count,
		    challenge_salt_size,
		    expires_ts
		from cap_challenge
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
		    expires_ts > ?
	`)
	if err != nil {
		return nil, err
	}
	d.useRedeemTokenStmt = stmt

	go d.delExpiredDaemon()

	return d, nil
}

func (d *Driver) delExpiredDaemon() {
	t := time.NewTicker(d.pruneInterval)
	for range t.C {
		if d.isClosed {
			return
		}

		res, err := d.delExpiredStmt.Exec(time.Now().Unix())
		if err != nil {
			d.logger.Error("failed to delete expired Cap challenges",
				"service", "sqlitedriver.Driver",
				"error", err,
			)
			continue
		}

		count, err := res.RowsAffected()
		if err != nil {
			d.logger.Error("failed to get number of deleted expired Cap challenges",
				"service", "sqlitedriver.Driver",
				"error", err,
			)
			continue
		}

		d.logger.Debug("deleted expired Cap challenges",
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
	if err := d.getIPCountStmt.Close(); err != nil {
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
	if ip != nil && d.rlOpts != nil {
		rl := d.rlOpts
		ipVer, ipInt := cap.IpToInt64(ip, rl.IPv4SignificantBits, rl.IPv6SignificantBits)
		ipVerPtr = &ipVer
		ipIntPtr = &ipInt
		windowStart := time.Now().Add(-rl.MaxChallengesWindow)

		row := d.getIPCountStmt.QueryRowContext(ctx, ipVer, ipInt, windowStart.Unix())

		var count int
		if err := row.Scan(&count); err != nil {
			return fmt.Errorf(`sqlitedriver: failed to get number of Cap challenges by IP %s: %w`, ip.String(), err)
		}

		if count > rl.MaxChallengesPerIP {
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
	row := d.getUnredeemedStmt.QueryRowContext(ctx, challengeToken, time.Now().Unix())

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
