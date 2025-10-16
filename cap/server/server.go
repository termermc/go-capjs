package server

import (
	"encoding/json"
	"errors"
	pkg "github.com/termermc/go-capjs/cap"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// ChallengeParamChooserFunc is a function that chooses challenge params based on a request.
// It can be used to dynamically select parameters based on things like the path, authentication, etc.
// If it returns an error, the error will be passed to the server's error handler.
type ChallengeParamChooserFunc func(req *http.Request) (pkg.ChallengeParams, error)

// NewStaticChallengeParamsChooser creates a new ChallengeParamChooserFunc that uses a static params struct.
// Will never return an error.
func NewStaticChallengeParamsChooser(params pkg.ChallengeParams) ChallengeParamChooserFunc {
	return func(req *http.Request) (pkg.ChallengeParams, error) {
		return params, nil
	}
}

// IPExtractorFunc is a function that extracts the client IP from a request.
// If the function returns nil, the IP cannot be determined.
type IPExtractorFunc func(req *http.Request) *netip.Addr

// RemoteAddrIPExtractor is an IPExtractorFunc that uses the request's remote address.
// This SHOULD NOT be used in environments where the application is behind a reverse proxy.
var RemoteAddrIPExtractor IPExtractorFunc = func(req *http.Request) *netip.Addr {
	remoteAddr := req.RemoteAddr

	colonIdx := strings.IndexByte(remoteAddr, ':')
	if colonIdx == -1 {
		return nil
	}

	addrPort, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		return nil
	}

	addr := addrPort.Addr()
	return &addr
}

// NewHeaderIPExtractor creates a new IPExtractorFunc that gets the request IP from a header.
// If the header is not present or does not contain a valid IP, the extractor returns nil.
// If the header is a comma-separated list, gets the leftmost entry.
//
// Example:
// NewHeaderIPExtractor("X-Forwarded-For")
func NewHeaderIPExtractor(header string) IPExtractorFunc {
	return func(req *http.Request) *netip.Addr {
		val := req.Header.Get(header)
		if val == "" {
			return nil
		}

		// Check if the header is a comma-separated list.
		// Use the leftmost item if so.
		var str string
		commaIdx := strings.IndexByte(val, ',')
		if commaIdx == -1 {
			str = val
		} else {
			str = str[:commaIdx]
		}

		// Try parsing IP.
		addr, err := netip.ParseAddr(str)
		if err != nil {
			return nil
		}

		return &addr
	}
}

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
	IpExtractor IPExtractorFunc
}

// Server is an implementation of the Cap server endpoints used to issue and validate challenges.
// It uses a Cap instance and its driver; it does not provide its own.
type Server struct {
	cap *pkg.Cap

	paramsFunc    ChallengeParamChooserFunc
	validDuration time.Duration
	ipFunc        IPExtractorFunc
	errFunc       ErrorHandlerFunc
}

// NewServer creates a new Cap server with the specified options.
func NewServer(cap *pkg.Cap, opts ...func(h *Server)) *Server {
	h := &Server{
		cap: cap,

		paramsFunc:    NewStaticChallengeParamsChooser(pkg.DefaultChallengeParams),
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
// To specify a dynamic params chooser, use WithChallengeParamsChooser.
func WithChallengeParams(params pkg.ChallengeParams) func(h *Server) {
	return func(h *Server) {
		h.paramsFunc = NewStaticChallengeParamsChooser(params)
	}
}

// WithChallengeParamsChooser sets the challenge params chooser to use when creating new challenges.
// When not specified, see comment on WithChallengeParams.
// If you just want to choose static params, use WithChallengeParamsChooser.
func WithChallengeParamsChooser(chooser ChallengeParamChooserFunc) func(h *Server) {
	return func(h *Server) {
		h.paramsFunc = chooser
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
func WithIPForRateLimit(ipFunc IPExtractorFunc) func(h *Server) {
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

	params, err := s.paramsFunc(req)
	if err != nil {
		s.errFunc(err, res, req)
		return
	}

	chalData, err := s.cap.CreateChallenge(ctx, pkg.ChallengeRequest{
		Params:        params,
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
