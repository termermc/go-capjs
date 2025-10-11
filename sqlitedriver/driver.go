package sqlitedriver

import (
	"context"
	"database/sql"
	"net/netip"

	"github.com/termermc/go-capjs/cap"
)

type DriverOptions struct {
}

type Driver struct {
}

func NewDriver(sqlite *sql.DB) (*Driver, error) {
	return nil, nil
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
