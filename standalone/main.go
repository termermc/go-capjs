package main

import (
	"os"
	"strings"
)

const envAdminKey = "ADMIN_KEY"

const envDataPath = "DATA_PATH"
const defDataPath = "./.data"

const envCorsOrigin = "CORS_ORIGIN"

const envRateLimitIPHeader = "RATELIMIT_IP_HEADER"

// Env is environment data for the standalone server.
type Env struct {
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
}

func main() {
	envData := &Env{}

	envData.AdminKey = os.Getenv(envAdminKey)
	if envData.AdminKey == "" {
		panic("Missing " + envAdminKey + " environment variable")
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

	// Try to create data directory.
	err := os.MkdirAll(envData.DataPath, 0o700)

	db, err := NewDB(envData)
	if err != nil {
		panic(err)
	}

	_ = db
}
