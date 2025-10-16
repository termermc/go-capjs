package main

import (
	"github.com/termermc/go-capjs/cap"
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

	httpServer := NewHttpServer(
		logger,
		c,
		db,
		env,
	)

	if err = httpServer.Listen(); err != nil {
		panic(err)
	}
}
