package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	// pgx stdlib driver registers "pgx" with database/sql
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/VividLogic-Software/agentauth/internal/audit"
	"github.com/VividLogic-Software/agentauth/internal/broker"
	"github.com/VividLogic-Software/agentauth/internal/envelope"
	"github.com/VividLogic-Software/agentauth/internal/identity"
	"github.com/VividLogic-Software/agentauth/internal/policy"
	"github.com/VividLogic-Software/agentauth/internal/storage"
)

// Services holds all initialized service dependencies for the AgentAuth server.
type Services struct {
	Issuer        *identity.Issuer
	Broker        *broker.CredentialBroker
	EnvSigner     *envelope.Signer
	EnvVerifier   *envelope.Verifier
	PolicyEngine  *policy.Engine
	AuditLog      *audit.AuditLog
	ChainVerifier *audit.ChainVerifier
	IdentityStore storage.IdentityStore
	TokenStore    storage.TokenStore
}

// initServices creates and wires all service dependencies from the given config.
func initServices(cfg *Config, log *zap.Logger) (*Services, func(), error) {
	var closers []func()
	cleanup := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	// ── PostgreSQL ─────────────────────────────────────────────────────────
	db, err := sql.Open("pgx", cfg.PostgresDSN)
	if err != nil {
		return nil, cleanup, fmt.Errorf("opening postgres: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, cleanup, fmt.Errorf("pinging postgres: %w", err)
	}
	closers = append(closers, func() { _ = db.Close() })
	log.Info("connected to postgres")

	dbAdapter := storage.NewSQLAdapter(db)

	// ── Redis ──────────────────────────────────────────────────────────────
	redisOpts := &redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	}
	redisClient := redis.NewClient(redisOpts)
	rCtx, rCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rCancel()
	if err := redisClient.Ping(rCtx).Err(); err != nil {
		_ = redisClient.Close()
		return nil, cleanup, fmt.Errorf("pinging redis: %w", err)
	}
	closers = append(closers, func() { _ = redisClient.Close() })
	log.Info("connected to redis")

	// ── Storage layer ──────────────────────────────────────────────────────
	identityStore := storage.NewPostgresIdentityStore(dbAdapter)
	pgTokenStore := storage.NewPostgresTokenStore(dbAdapter)
	redisCache := storage.NewRedisTokenCache(redisClient)
	tokenStore := storage.NewCachedTokenStore(pgTokenStore, redisCache)
	auditStore := storage.NewPostgresAuditStore(dbAdapter)

	// ── CA certificate and signing key ─────────────────────────────────────
	caCert, caKey, err := loadOrGenerateCA(cfg, log)
	if err != nil {
		return nil, cleanup, fmt.Errorf("loading CA: %w", err)
	}

	// ── Envelope signing key (ES256) ───────────────────────────────────────
	envelopeSigningKeyPEM, envelopePublicKeyPEM, err := loadOrGenerateEnvelopeKey(cfg, log)
	if err != nil {
		return nil, cleanup, fmt.Errorf("loading envelope signing key: %w", err)
	}

	envelopeIssuer := fmt.Sprintf("https://%s", cfg.TrustDomain)

	envSigner, err := envelope.NewSigner(envelopeSigningKeyPEM, envelopeIssuer)
	if err != nil {
		return nil, cleanup, fmt.Errorf("creating envelope signer: %w", err)
	}

	envVerifier, err := envelope.NewVerifier(envelopePublicKeyPEM, envelopeIssuer)
	if err != nil {
		return nil, cleanup, fmt.Errorf("creating envelope verifier: %w", err)
	}

	// ── Audit log ──────────────────────────────────────────────────────────
	auditLog, err := audit.NewAuditLog(auditStore, log)
	if err != nil {
		return nil, cleanup, fmt.Errorf("initializing audit log: %w", err)
	}
	chainVerifier := audit.NewChainVerifier(auditStore, log)

	// ── Identity issuer ────────────────────────────────────────────────────
	issuer := identity.NewIssuer(
		cfg.TrustDomain,
		caCert,
		caKey,
		identityStore,
		auditLog,
		log,
	)

	// ── Credential broker ──────────────────────────────────────────────────
	brokerKey := []byte(cfg.JWTSigningKey)
	if len(brokerKey) == 0 {
		brokerKey = make([]byte, 32)
		if _, err := rand.Read(brokerKey); err != nil {
			return nil, cleanup, fmt.Errorf("generating broker key: %w", err)
		}
		log.Warn("AGENTAUTH_JWT_SIGNING_KEY not set — using ephemeral key (tokens won't survive restarts)")
	}

	credBroker := broker.NewCredentialBroker(
		brokerKey,
		envelopeIssuer,
		tokenStore,
		auditLog,
		log,
	)

	// ── Policy engine ──────────────────────────────────────────────────────
	policyEngine := policy.NewEngine(policy.BuiltinPolicies, true)

	svc := &Services{
		Issuer:        issuer,
		Broker:        credBroker,
		EnvSigner:     envSigner,
		EnvVerifier:   envVerifier,
		PolicyEngine:  policyEngine,
		AuditLog:      auditLog,
		ChainVerifier: chainVerifier,
		IdentityStore: identityStore,
		TokenStore:    tokenStore,
	}

	return svc, cleanup, nil
}

// loadOrGenerateCA loads the CA cert/key from config files, or generates an
// ephemeral self-signed CA for development if no files are configured.
func loadOrGenerateCA(cfg *Config, log *zap.Logger) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if cfg.CACertFile != "" && cfg.SigningKeyFile != "" {
		certPEM, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, nil, fmt.Errorf("reading CA cert file %s: %w", cfg.CACertFile, err)
		}
		keyPEM, err := os.ReadFile(cfg.SigningKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("reading signing key file %s: %w", cfg.SigningKeyFile, err)
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, nil, fmt.Errorf("decoding CA cert PEM from %s", cfg.CACertFile)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing CA cert: %w", err)
		}

		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, nil, fmt.Errorf("decoding signing key PEM from %s", cfg.SigningKeyFile)
		}
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing signing key: %w", err)
		}

		log.Info("loaded CA certificate from file", zap.String("path", cfg.CACertFile))
		return cert, key, nil
	}

	// Development mode: generate ephemeral CA
	log.Warn("no CA cert/key files configured — generating ephemeral CA (development only)")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ephemeral CA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "AgentAuth Dev CA", Organization: []string{cfg.TrustDomain}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(87600 * time.Hour), // 10 years
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating ephemeral CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing ephemeral CA cert: %w", err)
	}
	return cert, key, nil
}

// loadOrGenerateEnvelopeKey loads or generates the ECDSA key pair used to sign
// and verify Agentic Identity Envelopes (ES256 JWTs).
// Returns the private key PEM and the public key PEM.
func loadOrGenerateEnvelopeKey(cfg *Config, log *zap.Logger) (string, string, error) {
	// For now: always generate an ephemeral key.
	// In production: load from cfg.SigningKeyFile or a KMS reference.
	log.Warn("generating ephemeral envelope signing key (tokens won't survive restarts — configure AGENTAUTH_SIGNING_KEY_FILE)")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generating envelope key: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshaling envelope private key: %w", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("marshaling envelope public key: %w", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))

	return privPEM, pubPEM, nil
}
