package server

import (
	"encoding/json"
	"errors"
	pkg "github.com/termermc/go-capjs/cap"
	"log/slog"
	"net/http"
	"net/netip"
	"time"
)

// IpExtractorFunc is a function that extracts the client IP from a request.
// If the function returns nil, the IP cannot be determined.
type IpExtractorFunc func(req *http.Request) *netip.Addr

// ErrorHandlerFunc is a function that handles an error and optionally writes an HTTP response.
// The error passed to it will never be nil.
type ErrorHandlerFunc func(err error, res http.ResponseWriter, req *http.Request)

var defaultErrFunc ErrorHandlerFunc = func(err error, res http.ResponseWriter, req *http.Request) {
	slog.Default().Error("Cap endpoint error",
		"service", "cap.Server",
		"error", err,
	)

	res.WriteHeader(500)
	_, _ = res.Write([]byte("internal error"))
}

// ChallengeHandlerOpts is options for Server.
type ChallengeHandlerOpts struct {
	// IpExtractor is the function used to extract the IP from a request.
	// It is used for rate limiting.
	// If unspecified/nil, rate limiting will be disabled.
	IpExtractor IpExtractorFunc
}

// Server is an implementation of the Cap server endpoints used to issue and validate challenges.
// It uses a Cap instance and its driver; it does not provide its own.
type Server struct {
	cap *pkg.Cap

	params        pkg.ChallengeParams
	validDuration time.Duration
	ipFunc        IpExtractorFunc
	errFunc       ErrorHandlerFunc
}

// NewServer creates a new Cap server with the specified options.
func NewServer(cap *pkg.Cap, opts ...func(h *Server)) *Server {
	h := &Server{
		cap: cap,

		params:        pkg.DefaultChallengeParams,
		validDuration: pkg.DefaultValidDuration,
		ipFunc:        nil,
		errFunc:       defaultErrFunc,
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// WithChallengeParams sets the parameters to use when creating new challenges.
// When not specified, uses cap.DefaultChallengeParams.
func WithChallengeParams(params pkg.ChallengeParams) func(h *Server) {
	return func(h *Server) {
		h.params = params
	}
}

// WithValidDuration sets the duration that a Cap challenge is valid before it expires.
// When not specified, uses cap.DefaultValidDuration.
func WithValidDuration(duration time.Duration) func(h *Server) {
	return func(h *Server) {
		h.validDuration = duration
	}
}

// WithIPForRateLimit uses the specified IP extractor function to pass IPs to the driver for rate limiting.
// Without an IP extractor function, the driver cannot perform rate limiting, even if it is enabled.
func WithIPForRateLimit(ipFunc IpExtractorFunc) func(h *Server) {
	return func(h *Server) {
		h.ipFunc = ipFunc
	}
}

// WithErrorHandler sets a function to handle errors in the HTTP handlers.
// The function is called when an error occurs, such as when the Cap driver returns an error.
func WithErrorHandler(errFunc ErrorHandlerFunc) func(h *Server) {
	return func(h *Server) {
		h.errFunc = errFunc
	}
}

// ChallengeHandler is the HTTP handler that issues new challenges.
// Should be mounted on `/challenge`.
func (s *Server) ChallengeHandler(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		res.WriteHeader(405)
		_, _ = res.Write([]byte("method not allowed"))
		return
	}

	ctx := req.Context()

	var ip *netip.Addr
	if s.ipFunc != nil {
		ip = s.ipFunc(req)
	}

	chalData, err := s.cap.CreateChallenge(ctx, pkg.ChallengeRequest{
		Params:        s.params,
		IP:            ip,
		ValidDuration: s.validDuration,
	})
	if err != nil {
		if errors.Is(err, pkg.ErrRateLimited) {
			res.WriteHeader(429)
			_, _ = res.Write([]byte("rate limited, try again later"))
			return
		}

		s.errFunc(err, res, req)
		return
	}

	enc := json.NewEncoder(res)
	_ = enc.Encode(chalData.ToResponse())
}

// RedeemHandler is the HTTP handler that accepts solutions and verifies them, returning a redeem token if correct and valid.
// Should be mounted on `/redeem`.
func (s *Server) RedeemHandler(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		res.WriteHeader(405)
		_, _ = res.Write([]byte("method not allowed"))
		return
	}

	type redeemRes struct {
		Success bool   `json:"success"`
		Message string `json:"message,omitempty"`
		Token   string `json:"token,omitempty"`

		// UNIX millisecond timestamp when the token expires.
		Expires int64 `json:"expires,omitempty"`
	}

	doJson := func(status int, data redeemRes) {
		res.WriteHeader(status)
		enc := json.NewEncoder(res)
		_ = enc.Encode(data)
	}

	// Decode request body.
	var body pkg.VerifySolutionsRequest
	defer func() {
		_ = req.Body.Close()
	}()
	dec := json.NewDecoder(req.Body)
	if dec.Decode(&body) != nil {
		// We don't really care about why it failed, just return 400.
		doJson(400, redeemRes{
			Success: false,
			Message: "malformed request body, expected JSON body with token and solutions",
		})
		return
	}

	ctx := req.Context()

	redeemData, err := s.cap.VerifyChallengeSolutions(ctx, body)
	if err != nil {
		if errors.Is(err, pkg.ErrChallengeNotFound) {
			doJson(404, redeemRes{
				Success: false,
				Message: "invalid token",
			})
			return
		}

		if errors.Is(err, pkg.ErrInsufficientSolutions) {
			doJson(400, redeemRes{
				Success: false,
				Message: "insufficient solutions provided",
			})
			return
		}

		if errors.Is(err, pkg.ErrInvalidSolution) {
			doJson(403, redeemRes{
				Success: false,
				Message: "invalid solution",
			})
			return
		}

		s.errFunc(err, res, req)
		return
	}

	doJson(200, redeemRes{
		Success: true,
		Token:   redeemData.RedeemToken,
		Expires: redeemData.Expires.UnixMilli(),
	})
	return
}
