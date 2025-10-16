package main

import (
	"github.com/termermc/go-capjs/cap"
	"os"
	"strconv"
	"strings"
)

const envServerPort = "SERVER_PORT"
const defServerPort = 3000

const envServerHostname = "SERVER_HOSTNAME"
const defServerHostname = "0.0.0.0"

const envAdminKey = "ADMIN_KEY"

const envDataPath = "DATA_PATH"
const defDataPath = "./.data"

const envCorsOrigin = "CORS_ORIGIN"

const envRateLimitIPHeader = "RATELIMIT_IP_HEADER"

const envRateLimitMaxChallengesPerIP = "RATELIMIT_MAX_CHALLENGES_PER_IP"
const envRateLimitMaxChallengesWindowSeconds = "RATELIMIT_MAX_CHALLENGES_WINDOW_SECONDS"

// Env is environment data for the standalone server.
type Env struct {
	// ServerPort is the port for the server to listen on.
	ServerPort int

	// ServerHostname is the hostname for the server to listen on.
	ServerHostname string

	// The admin key.
	// Used as a password for authenticating.
	AdminKey string

	// The data storage path.
	DataPath string

	// The allowed CORS origins.
	// An empty/nil slice means that all origins are allowed.
	CorsOrigins []string

	// The header to use for extracting the request IP.
	// If empty, uses the remote address (not recommended).
	RateLimitIPHeader string

	// RateLimitMaxChallengesPerIP is the maximum number of challenge creations to allow per IP within a window of time.
	RateLimitMaxChallengesPerIP int

	// RateLimitMaxChallengesWindowSeconds is the window (in seconds) to count challenge creations for rate limiting.
	RateLimitMaxChallengesWindowSeconds int
}

func MustGetenvInt(name string, orDef *int64) int64 {
	env := os.Getenv(name)
	if env == "" {
		if orDef == nil {
			panic("Missing environment variable " + env)
		}

		return *orDef
	}

	val, err := strconv.ParseInt(env, 10, 64)
	if err != nil {
		panic("Environment variable " + env + " must be an integer")
	}

	return val
}

// MustResolveEnv resolves an Env from environment variables.
// It will panic if anything is invalid.
func MustResolveEnv() *Env {
	envData := &Env{}

	{
		def := int64(defServerPort)
		envData.ServerPort = int(MustGetenvInt(envServerPort, &def))
	}

	if env := os.Getenv(envServerHostname); env == "" {
		envData.ServerHostname = defServerHostname
	} else {
		envData.ServerHostname = env
	}

	envData.AdminKey = os.Getenv(envAdminKey)
	if envData.AdminKey == "" {
		panic("Missing " + envAdminKey + " environment variable")
	}
	if len(envData.AdminKey) < 32 {
		panic(envAdminKey + " must be at least 32 characters long")
	}

	if env := os.Getenv(envDataPath); env == "" {
		envData.DataPath = defDataPath
	} else {
		envData.DataPath = env
	}

	if env := os.Getenv(envCorsOrigin); env != "" {
		envData.CorsOrigins = strings.Split(env, ",")
	}

	if env := os.Getenv(envRateLimitIPHeader); env != "" {
		envData.RateLimitIPHeader = env
	}

	{
		def := int64(cap.DefaultMaxChallengesPerIP)
		envData.RateLimitMaxChallengesPerIP = int(MustGetenvInt(envRateLimitMaxChallengesPerIP, &def))
	}

	{
		def := int64(cap.DefaultMaxChallengesWindow.Seconds())
		envData.RateLimitMaxChallengesWindowSeconds = int(MustGetenvInt(envRateLimitMaxChallengesWindowSeconds, &def))
	}

	return envData
}
