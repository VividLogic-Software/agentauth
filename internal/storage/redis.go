package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// keyPrefixRevoked is the Redis key prefix for revoked token JTIs.
	keyPrefixRevoked = "agentauth:revoked:"

	// keyPrefixToken is the Redis key prefix for cached token records.
	keyPrefixToken = "agentauth:token:"

	// keyPrefixIdentity is the Redis key prefix for cached identity records.
	keyPrefixIdentity = "agentauth:identity:"

	// DefaultCacheTTL is the default cache entry TTL.
	DefaultCacheTTL = 10 * time.Minute
)

// RedisTokenCache provides a fast revocation check and token cache backed by Redis.
// It is used as a read-through cache in front of the PostgreSQL token store.
type RedisTokenCache struct {
	client *redis.Client
}

// NewRedisTokenCache creates a new Redis-backed token cache.
func NewRedisTokenCache(client *redis.Client) *RedisTokenCache {
	return &RedisTokenCache{client: client}
}

// IsRevoked returns true if the given JTI has been recorded as revoked in Redis.
// This is the hot path for token validation — O(1) Redis GET.
func (c *RedisTokenCache) IsRevoked(ctx context.Context, jti string) (bool, error) {
	key := keyPrefixRevoked + jti
	result, err := c.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking revocation for %s: %w", jti, err)
	}
	return result == "1", nil
}

// MarkRevoked records a token JTI as revoked in Redis with the given TTL.
// The TTL should match the token's remaining lifetime to prevent unbounded growth.
func (c *RedisTokenCache) MarkRevoked(ctx context.Context, jti string, ttl time.Duration) error {
	key := keyPrefixRevoked + jti
	if err := c.client.Set(ctx, key, "1", ttl).Err(); err != nil {
		return fmt.Errorf("marking token %s as revoked: %w", jti, err)
	}
	return nil
}

// CacheToken stores a token record in Redis for fast reads.
func (c *RedisTokenCache) CacheToken(ctx context.Context, record *TokenRecord) error {
	key := keyPrefixToken + record.JTI
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshaling token record: %w", err)
	}

	ttl := time.Until(record.ExpiresAt)
	if ttl <= 0 {
		return nil // Don't cache already-expired tokens
	}

	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("caching token %s: %w", record.JTI, err)
	}
	return nil
}

// GetCachedToken retrieves a token record from Redis, returning nil if not found.
func (c *RedisTokenCache) GetCachedToken(ctx context.Context, jti string) (*TokenRecord, error) {
	key := keyPrefixToken + jti
	data, err := c.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting cached token %s: %w", jti, err)
	}

	var record TokenRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("unmarshaling token record: %w", err)
	}
	return &record, nil
}

// CacheIdentity stores an identity record in Redis for fast reads.
func (c *RedisTokenCache) CacheIdentity(ctx context.Context, record *IdentityRecord) error {
	key := keyPrefixIdentity + record.ID
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshaling identity record: %w", err)
	}

	ttl := time.Until(record.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	// Cap cache TTL to avoid stale revocation state
	if ttl > DefaultCacheTTL {
		ttl = DefaultCacheTTL
	}

	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("caching identity %s: %w", record.ID, err)
	}
	return nil
}

// GetCachedIdentity retrieves an identity record from Redis, returning nil if not cached.
func (c *RedisTokenCache) GetCachedIdentity(ctx context.Context, agentID string) (*IdentityRecord, error) {
	key := keyPrefixIdentity + agentID
	data, err := c.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting cached identity %s: %w", agentID, err)
	}

	var record IdentityRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("unmarshaling identity record: %w", err)
	}
	return &record, nil
}

// InvalidateIdentity removes an identity from the cache, forcing a fresh read from Postgres.
// This should be called whenever an identity is revoked.
func (c *RedisTokenCache) InvalidateIdentity(ctx context.Context, agentID string) error {
	key := keyPrefixIdentity + agentID
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("invalidating identity cache for %s: %w", agentID, err)
	}
	return nil
}

// CachedTokenStore wraps a PostgresTokenStore with a Redis read-through cache.
type CachedTokenStore struct {
	pg    *PostgresTokenStore
	cache *RedisTokenCache
}

// NewCachedTokenStore creates a token store with a Redis cache layer.
func NewCachedTokenStore(pg *PostgresTokenStore, cache *RedisTokenCache) *CachedTokenStore {
	return &CachedTokenStore{pg: pg, cache: cache}
}

// StoreToken persists a token and warms the cache.
func (s *CachedTokenStore) StoreToken(ctx context.Context, record *TokenRecord) error {
	if err := s.pg.StoreToken(ctx, record); err != nil {
		return err
	}
	// Best-effort cache warm — don't fail the write if caching fails
	_ = s.cache.CacheToken(ctx, record)
	return nil
}

// GetToken retrieves a token, checking the cache first.
func (s *CachedTokenStore) GetToken(ctx context.Context, jti string) (*TokenRecord, error) {
	// Fast path: check cache
	if cached, err := s.cache.GetCachedToken(ctx, jti); err == nil && cached != nil {
		// Check revocation overlay
		revoked, err := s.cache.IsRevoked(ctx, jti)
		if err == nil && revoked {
			cached.Revoked = true
		}
		return cached, nil
	}

	// Slow path: read from Postgres
	record, err := s.pg.GetToken(ctx, jti)
	if err != nil {
		return nil, err
	}

	// Warm the cache
	_ = s.cache.CacheToken(ctx, record)
	return record, nil
}

// RevokeToken revokes a token in both Postgres and Redis.
func (s *CachedTokenStore) RevokeToken(ctx context.Context, jti string) error {
	// Get token to find its expiry for the Redis TTL
	record, err := s.GetToken(ctx, jti)
	if err != nil {
		return fmt.Errorf("looking up token for revocation: %w", err)
	}

	if err := s.pg.RevokeToken(ctx, jti); err != nil {
		return err
	}

	ttl := time.Until(record.ExpiresAt)
	if ttl > 0 {
		_ = s.cache.MarkRevoked(ctx, jti, ttl)
	}

	return nil
}

// RevokeAllForAgent revokes all tokens for an agent in Postgres.
func (s *CachedTokenStore) RevokeAllForAgent(ctx context.Context, agentID string) error {
	return s.pg.RevokeAllForAgent(ctx, agentID)
}
