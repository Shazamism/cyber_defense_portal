package envelope

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SourceInfo details the sending connector and vendor system.
type SourceInfo struct {
	SourceID         string `json:"source_id"`
	SourceType       string `json:"source_type"`
	Vendor           string `json:"vendor"`
	ConnectorVersion string `json:"connector_version"`
}

// CanonicalEnvelope represents the standardized v1.0 event envelope for all accepted security events.
type CanonicalEnvelope struct {
	EventID        string          `json:"event_id"`
	EventType      string          `json:"event_type"`
	EventVersion   string          `json:"event_version"`
	TenantID       string          `json:"tenant_id"`
	Source         SourceInfo      `json:"source"`
	OccurredAt     string          `json:"occurred_at"`
	ReceivedAt     string          `json:"received_at"`
	TraceID        string          `json:"trace_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	Classification string          `json:"classification"`
	PriorityHint   string          `json:"priority_hint"`
	PayloadFormat  string          `json:"payload_format"`
	PayloadHash    string          `json:"payload_hash"`
	Payload        json.RawMessage `json:"payload"`
}

// GenerateEventID creates a unique prefixed event ID.
func GenerateEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("evt_%d%s", time.Now().UnixMilli(), hex.EncodeToString(b)[:8])
}

// CalculatePayloadHash computes the sha256 checksum of the raw payload bytes.
func CalculatePayloadHash(payload []byte) string {
	h := sha256.New()
	h.Write(payload)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// NewCanonicalEnvelope builds and validates a CanonicalEnvelope from raw event components.
func NewCanonicalEnvelope(
	eventType string,
	tenantID string,
	source SourceInfo,
	occurredAt string,
	traceID string,
	idempotencyKey string,
	priorityHint string,
	payloadFormat string,
	payloadBytes []byte,
) (*CanonicalEnvelope, error) {
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	if source.SourceID == "" {
		return nil, errors.New("source.source_id is required")
	}
	if idempotencyKey == "" {
		return nil, errors.New("idempotency_key is required")
	}
	if len(payloadBytes) == 0 {
		return nil, errors.New("payload cannot be empty")
	}

	if eventType == "" {
		eventType = "security.alert.received"
	}
	if priorityHint == "" {
		priorityHint = "medium"
	}
	if payloadFormat == "" {
		payloadFormat = "vendor-json"
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if occurredAt == "" {
		occurredAt = now
	}

	if traceID == "" {
		tb := make([]byte, 16)
		_, _ = rand.Read(tb)
		traceID = hex.EncodeToString(tb)
	}

	payloadHash := CalculatePayloadHash(payloadBytes)

	return &CanonicalEnvelope{
		EventID:        GenerateEventID(),
		EventType:      eventType,
		EventVersion:   "1.0",
		TenantID:       tenantID,
		Source:         source,
		OccurredAt:     occurredAt,
		ReceivedAt:     now,
		TraceID:        traceID,
		IdempotencyKey: idempotencyKey,
		Classification: "security-event",
		PriorityHint:   priorityHint,
		PayloadFormat:  payloadFormat,
		PayloadHash:    payloadHash,
		Payload:        json.RawMessage(payloadBytes),
	}, nil
}
