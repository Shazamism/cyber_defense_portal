package ratelimit

import (
	"sync"
	"time"
)

// TokenBucket implements a simple thread-safe token bucket algorithm.
type TokenBucket struct {
	capacity   float64
	tokens     float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

func NewTokenBucket(capacity, refillRate float64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

func (tb *TokenBucket) Allow() (bool, int) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.lastRefill = now

	tb.tokens = tb.tokens + (elapsed * tb.refillRate)
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true, 0
	}

	// Calculate retry after seconds
	missing := 1.0 - tb.tokens
	retryAfter := int(missing / tb.refillRate)
	if retryAfter < 1 {
		retryAfter = 1
	}
	return false, retryAfter
}

// LimiterManager holds per-key token buckets.
type LimiterManager struct {
	mu      sync.RWMutex
	buckets map[string]*TokenBucket
	rate    float64
	burst   float64
}

func NewLimiterManager(defaultRate float64, defaultBurst float64) *LimiterManager {
	return &LimiterManager{
		buckets: make(map[string]*TokenBucket),
		rate:    defaultRate,
		burst:   defaultBurst,
	}
}

// CheckRateLimit returns (allowed, retryAfterSeconds).
func (lm *LimiterManager) CheckRateLimit(key string) (bool, int) {
	lm.mu.Lock()
	bucket, exists := lm.buckets[key]
	if !exists {
		bucket = NewTokenBucket(lm.burst, lm.rate)
		lm.buckets[key] = bucket
	}
	lm.mu.Unlock()

	return bucket.Allow()
}
