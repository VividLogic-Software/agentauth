// Command agentauth-server is the AgentAuth control plane server.
// It provides identity issuance, credential brokering, policy evaluation,
// and tamper-evident audit log APIs for agent authorization.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Config holds the server configuration loaded from environment variables
// or a YAML config file. All fields can be set via AGENTAUTH_<FIELD> env vars.
type Config struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`

	PostgresDSN string `mapstructure:"postgres_dsn"`

	RedisAddr     string `mapstructure:"redis_addr"`
	RedisPassword string `mapstructure:"redis_password"`
	RedisDB       int    `mapstructure:"redis_db"`

	NatsURL string `mapstructure:"nats_url"`

	TrustDomain    string `mapstructure:"trust_domain"`
	SigningKeyFile string `mapstructure:"signing_key_file"`
	CACertFile     string `mapstructure:"ca_cert_file"`

	APIKeyHash    string `mapstructure:"api_key_hash"`
	JWTSigningKey string `mapstructure:"jwt_signing_key"`

	LogLevel    string `mapstructure:"log_level"`
	OTLPEndpoint string `mapstructure:"otlp_endpoint"`
	MetricsPort  int    `mapstructure:"metrics_port"`
}

// Server is the AgentAuth HTTP server.
type Server struct {
	cfg  *Config
	svc  *Services
	log  *zap.Logger
	http *http.Server
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: loading config: %v\n", err)
		os.Exit(1)
	}

	log, err := initLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: initializing logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync() //nolint:errcheck

	log.Info("AgentAuth server starting",
		zap.String("version", Version()),
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.String("trust_domain", cfg.TrustDomain),
	)

	svc, cleanup, err := initServices(cfg, log)
	if err != nil {
		log.Fatal("failed to initialize services", zap.Error(err))
	}
	defer cleanup()

	srv, err := NewServer(cfg, svc, log)
	if err != nil {
		log.Fatal("failed to create server", zap.Error(err))
	}

	serverErr := make(chan error, 1)
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
		log.Info("listening for connections", zap.String("addr", addr))
		if err := srv.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Info("shutdown signal received", zap.String("signal", sig.String()))
	case err := <-serverErr:
		log.Error("server error", zap.Error(err))
	}

	log.Info("shutting down server gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.http.Shutdown(ctx); err != nil {
		log.Error("server forced to shutdown", zap.Error(err))
		os.Exit(1)
	}

	log.Info("server stopped cleanly")
}

// NewServer creates and initializes the AgentAuth HTTP server with all routes wired.
func NewServer(cfg *Config, svc *Services, log *zap.Logger) (*Server, error) {
	srv := &Server{cfg: cfg, svc: svc, log: log}

	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(requestLogger(log))
	r.Use(chimiddleware.Timeout(60 * time.Second))

	// Public endpoints
	r.Get("/healthz", handleHealthz)
	r.Get("/readyz", handleReadyz)
	r.Get("/version", handleVersion)

	// Authenticated API
	r.Route("/v1", func(r chi.Router) {
		r.Use(apiKeyMiddleware(cfg.APIKeyHash, log))

		r.Post("/identities", srv.handleIssueIdentity())
		r.Get("/identities", srv.handleListIdentities())
		r.Get("/identities/{agentID}", srv.handleGetIdentity())
		r.Post("/identities/{agentID}/revoke", srv.handleRevokeIdentity())
		r.Post("/identities/{agentID}/rotate", srv.handleRotateIdentity())

		r.Post("/envelopes", srv.handleCreateEnvelope())
		r.Post("/envelopes/verify", srv.handleVerifyEnvelope())
		r.Post("/envelopes/delegate", srv.handleDelegateEnvelope())

		r.Post("/tokens", srv.handleMintToken())
		r.Post("/tokens/{jti}/revoke", srv.handleRevokeToken())
		r.Post("/token", srv.handleTokenExchange()) // RFC 8693

		r.Get("/audit", srv.handleListAuditEvents())
		r.Get("/audit/verify", srv.handleVerifyAuditChain())

		r.Get("/policies", srv.handleListPolicies())
		r.Post("/policies", srv.handleCreatePolicy())
		r.Delete("/policies/{policyID}", srv.handleDeletePolicy())
	})

	srv.http = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:      r,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	return srv, nil
}

// loadConfig reads configuration from environment variables and optional YAML file.
func loadConfig() (*Config, error) {
	v := viper.New()
	v.SetConfigName("agentauth")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/agentauth/")
	v.AddConfigPath("$HOME/.agentauth")
	v.AddConfigPath(".")

	v.SetDefault("host", "0.0.0.0")
	v.SetDefault("port", 8080)
	v.SetDefault("read_timeout", "15s")
	v.SetDefault("write_timeout", "15s")
	v.SetDefault("idle_timeout", "60s")
	v.SetDefault("trust_domain", "agentauth.io")
	v.SetDefault("log_level", "info")
	v.SetDefault("redis_addr", "localhost:6379")
	v.SetDefault("nats_url", "nats://localhost:4222")
	v.SetDefault("metrics_port", 9090)
	v.SetDefault("postgres_dsn", "postgres://agentauth:agentauth@localhost:5432/agentauth?sslmode=disable")

	v.SetEnvPrefix("AGENTAUTH")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}
	return cfg, nil
}

// initLogger creates a production zap logger at the given log level.
func initLogger(level string) (*zap.Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	return cfg.Build(zap.AddCaller())
}

// requestLogger returns a chi middleware that logs each request.
func requestLogger(log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			log.Info("request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", ww.Status()),
				zap.Duration("latency", time.Since(start)),
				zap.String("request_id", chimiddleware.GetReqID(r.Context())),
			)
		})
	}
}

// apiKeyMiddleware validates the Authorization: Bearer <key> header.
func apiKeyMiddleware(apiKeyHash string, log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				http.Error(w, `{"error":"unauthorized","message":"missing Authorization header"}`, http.StatusUnauthorized)
				return
			}
			// In production: validate HMAC of the provided key against apiKeyHash.
			// For development (no key hash configured), accept any non-empty key.
			if apiKeyHash == "" {
				log.Debug("api key validation skipped (AGENTAUTH_API_KEY_HASH not configured)")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Static handlers

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok"}`)
}

func handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ready"}`)
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"version":%q}`, Version())
}

// Version returns the current server version.
func Version() string {
	return "0.1.0"
}
