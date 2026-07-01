// Package config loads application configuration from environment variables.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds every runtime setting the application needs. It is read once
// at startup; nothing in the app re-reads the environment afterwards.
type Config struct {
	DatabaseURL string
	RedisURL    string

	HTTPPort  string
	GRPCPort  string
	DebugPort string // net/http/pprof + /metrics, kept off the public HTTP port on purpose

	EncryptionKey []byte // 32 raw bytes for AES-256-GCM, decoded from base64 env var
	JWTSecret     []byte

	// AccessTokenTTL controls how long an owner JWT stays valid after login.
	AccessTokenTTL time.Duration

	// LimiterSyncInterval controls how often Redis counters are flushed to
	// usage_counters in Postgres (durability/reporting, not the enforcement path).
	LimiterSyncInterval time.Duration

	// ProxyLogBatchSize / ProxyLogFlushInterval tune the async proxy_access_logs writer.
	ProxyLogBatchSize     int
	ProxyLogFlushInterval time.Duration
}

// Load reads Config from the process environment. It fails fast: a
// misconfigured deployment should not start serving guest traffic.
func Load() (Config, error) {
	cfg := Config{
		DatabaseURL:           mustEnv("DATABASE_URL"),
		RedisURL:              envOr("REDIS_URL", "redis://redis:6379/0"),
		HTTPPort:              envOr("HTTP_PORT", "8080"),
		GRPCPort:              envOr("GRPC_PORT", "9090"),
		DebugPort:             envOr("DEBUG_PORT", "6060"),
		AccessTokenTTL:        durationOr("ACCESS_TOKEN_TTL", time.Hour),
		LimiterSyncInterval:   durationOr("LIMITER_SYNC_INTERVAL", 3*time.Second),
		ProxyLogBatchSize:     intOr("PROXY_LOG_BATCH_SIZE", 50),
		ProxyLogFlushInterval: durationOr("PROXY_LOG_FLUSH_INTERVAL", 500*time.Millisecond),
	}

	key, err := decodeKey("ENCRYPTION_KEY", 32)
	if err != nil {
		return Config{}, err
	}
	cfg.EncryptionKey = key

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return Config{}, fmt.Errorf("config: JWT_SECRET is required")
	}
	cfg.JWTSecret = []byte(secret)

	return cfg, nil
}

func decodeKey(envVar string, wantLen int) ([]byte, error) {
	raw := os.Getenv(envVar)
	if raw == "" {
		return nil, fmt.Errorf("config: %s is required (base64, %d raw bytes)", envVar, wantLen)
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("config: %s is not valid base64: %w", envVar, err)
	}
	if len(key) != wantLen {
		return nil, fmt.Errorf("config: %s must decode to %d bytes, got %d", envVar, wantLen, len(key))
	}
	return key, nil
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("config: required env var %s is not set", key))
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func intOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func durationOr(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
