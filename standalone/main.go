package main

import (
	"fmt"
	"github.com/termermc/go-capjs/cap"
	"github.com/termermc/go-capjs/cap/server"
	"github.com/termermc/go-capjs/sqlitedriver"
	"log/slog"
	"os"
	"time"
)

func main() {
	jsonLogHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{})
	logger := slog.New(jsonLogHandler)

	env := MustResolveEnv()

	// Try to create data directory.
	err := os.MkdirAll(env.DataPath, 0o700)

	db, err := NewDB(env)
	if err != nil {
		panic(err)
	}

	var ipFunc server.IPExtractorFunc
	if env.RateLimitIPHeader == "" {
		ipFunc = server.RemoteAddrIPExtractor
		_, _ = fmt.Fprintf(os.Stderr, "Warning: Using direct IP from requests for rate limiting. If you are using a reverse proxy, please set RATELIMIT_IP_HEADER to the header that contains the request IP.\n")
	} else {
		ipFunc = server.NewHeaderIPExtractor(env.RateLimitIPHeader)
	}

	driver, err := sqlitedriver.NewDriver(db.CapDB,
		sqlitedriver.WithRateLimit(
			cap.WithMaxChallengesPerIP(env.RateLimitMaxChallengesPerIP),
			cap.WithMaxChallengesWindow(time.Duration(env.RateLimitMaxChallengesWindowSeconds)*time.Second),
		),
	)
	if err != nil {
		panic(err)
	}

	c := cap.NewCap(driver)

	capServer := NewHttpServer(
		logger,
		c,
		db,
		env,
		ipFunc,
	)

	_ = capServer
}
