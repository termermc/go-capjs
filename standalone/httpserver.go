package main

import (
	"fmt"
	"github.com/termermc/go-capjs/cap"
	"github.com/termermc/go-capjs/cap/server"
	"log/slog"
	"net/http"
)

type HttpServer struct {
	logger    *slog.Logger
	cap       *cap.Cap
	capServer *server.Server
	db        *DB
	env       *Env
	ipFunc    server.IPExtractorFunc
}

func NewHttpServer(
	logger *slog.Logger,
	c *cap.Cap,
	db *DB,
	env *Env,
) *HttpServer {
	errJson := []byte(`{"success":false,"message":"internal error"}`)

	var ipFunc server.IPExtractorFunc
	if env.RateLimitIPHeader == "" {
		ipFunc = server.RemoteAddrIPExtractor
	} else {
		ipFunc = server.NewHeaderIPExtractor(env.RateLimitIPHeader)
	}

	capServer := server.NewServer(c,
		server.WithErrorHandler(func(err error, res http.ResponseWriter, req *http.Request) {
			logger.Error("internal error in Cap endpoint",
				"error", err,
				"url", req.URL.String(),
			)

			res.Header().Set("Content-Type", "application/json")
			res.WriteHeader(500)
			_, _ = res.Write(errJson)
		}),
		server.WithIPForRateLimit(ipFunc),
		server.WithChallengeParamsChooser(func(req *http.Request) (cap.ChallengeParams, error) {
			siteKey := req.PathValue("site_key")
			_ = siteKey

			// TODO Use PathValue to get site key, then fetch params from there.
			return cap.DefaultChallengeParams, nil
		}),
	)

	return &HttpServer{
		logger:    logger,
		cap:       c,
		capServer: capServer,
		db:        db,
		env:       env,
	}
}

func (s *HttpServer) Listen() error {
	addr := fmt.Sprintf("%s:%d", s.env.ServerHostname, s.env.ServerPort)

	mux := http.NewServeMux()

	mux.HandleFunc("/{site_key}/api/challenge", s.capServer.ChallengeHandler)
	mux.HandleFunc("/{site_key}/api/redeem", s.capServer.RedeemHandler)

	s.logger.Info("HTTP server is listening",
		"address", addr,
	)
	return http.ListenAndServe(addr, mux)
}
