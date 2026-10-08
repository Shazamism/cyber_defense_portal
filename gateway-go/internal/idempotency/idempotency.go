package idempotency

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrHashMismatch = errors.New("source-integrity issue: payload hash does not match previous submission for idempotency key")
)

// Record stores the result of an accepted event for duplicate detection.
type Record struct {
	TenantID        string    `json:"tenant_id"`
	SourceID        string    `json:"source_id"`
	IdempotencyKey  string    `json:"idempotency_key"`
	PlatformEventID string    `json:"platform_event_id"`
	FirstSeen       time.Time `json:"first_seen"`
	PayloadHash     string    `json:"payload_hash"`
	AcceptanceCode  int       `json:"acceptance_code"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// Store maintains in-memory idempotency state with 24-hour expiration.
type Store struct {
	mu            sync.RWMutex
	records       map[string]*Record
	defaultWindow time.Duration
}

// NewStore initializes an Idempotency Store.
func NewStore(defaultWindow time.Duration) *Store {
	if defaultWindow <= 0 {
		defaultWindow = 24 * time.Hour
	}
	s := &Store{
		records:       make(map[string]*Record),
		defaultWindow: defaultWindow,
	}
	// Background cleanup routine
	go s.cleanupExpired()
	return s
}

func makeKey(tenantID, sourceID, idempotencyKey string) string {
	return fmt.Sprintf("%s:%s:%s", tenantID, sourceID, idempotencyKey)
}

// CheckOrStore checks if an idempotency key exists.
// Returns (existingRecord, isDuplicate, error).
func (s *Store) CheckOrStore(tenantID, sourceID, idempotencyKey, platformEventID, payloadHash string) (*Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	compositeKey := makeKey(tenantID, sourceID, idempotencyKey)
	now := time.Now()

	if rec, exists := s.records[compositeKey]; exists {
		if now.Before(rec.ExpiresAt) {
			if rec.PayloadHash != payloadHash {
				return nil, false, ErrHashMismatch
			}
			return rec, true, nil
		}
		delete(s.records, compositeKey)
	}

	newRec := &Record{
		TenantID:        tenantID,
		SourceID:        sourceID,
		IdempotencyKey:  idempotencyKey,
		PlatformEventID: platformEventID,
		FirstSeen:       now,
		PayloadHash:     payloadHash,
		AcceptanceCode:  202,
		ExpiresAt:       now.Add(s.defaultWindow),
	}
	s.records[compositeKey] = newRec
	return newRec, false, nil
}

func (s *Store) cleanupExpired() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for k, v := range s.records {
			if now.After(v.ExpiresAt) {
				delete(s.records, k)
			}
		}
		s.mu.Unlock()
	}
}
