package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/defence-cyber-portal/integration-gateway/internal/envelope"
)

// Topic names per Section 5.2
const (
	TopicRawIngress = "security.ingress.raw.v1"
	TopicQuarantine = "security.quarantine.v1"
	TopicDLQ        = "security.dlq.gateway.v1"
)

// PublishResult holds the metadata returned upon successful publication to the event bus.
type PublishResult struct {
	Topic     string    `json:"topic"`
	Partition int32     `json:"partition"`
	Offset    int64     `json:"offset"`
	Timestamp time.Time `json:"timestamp"`
}

// Publisher defines the contract for sending events to the event bus.
type Publisher interface {
	Publish(ctx context.Context, topic string, partitionKey string, env *envelope.CanonicalEnvelope) (*PublishResult, error)
	PublishQuarantine(ctx context.Context, reason string, rawData []byte) (*PublishResult, error)
	Close() error
}

// InMemKafkaPublisher simulates an idempotent Kafka broker cluster with partition assignment and monotonic offsets.
type InMemKafkaPublisher struct {
	mu           sync.Mutex
	topics       map[string][]envelope.CanonicalEnvelope
	offsets      map[string]int64
	numPartitions int32
}

func NewInMemKafkaPublisher(numPartitions int32) *InMemKafkaPublisher {
	if numPartitions <= 0 {
		numPartitions = 12
	}
	return &InMemKafkaPublisher{
		topics:        make(map[string][]envelope.CanonicalEnvelope),
		offsets:       make(map[string]int64),
		numPartitions: numPartitions,
	}
}

func (p *InMemKafkaPublisher) Publish(ctx context.Context, topic string, partitionKey string, env *envelope.CanonicalEnvelope) (*PublishResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.offsets[topic]++
	offset := p.offsets[topic]
	p.topics[topic] = append(p.topics[topic], *env)

	// Hash partition key to select partition
	var hash uint32
	for _, c := range partitionKey {
		hash = (hash * 31) + uint32(c)
	}
	partition := int32(hash % uint32(p.numPartitions))

	return &PublishResult{
		Topic:     topic,
		Partition: partition,
		Offset:    offset,
		Timestamp: time.Now().UTC(),
	}, nil
}

func (p *InMemKafkaPublisher) PublishQuarantine(ctx context.Context, reason string, rawData []byte) (*PublishResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.offsets[TopicQuarantine]++
	offset := p.offsets[TopicQuarantine]

	// Wrap in minimal quarantine envelope
	quarantineObj := map[string]interface{}{
		"quarantine_reason": reason,
		"quarantined_at":    time.Now().UTC(),
		"raw_payload_len":   len(rawData),
	}
	rawBytes, _ := json.Marshal(quarantineObj)
	env := envelope.CanonicalEnvelope{
		EventID:        envelope.GenerateEventID(),
		EventType:      "security.quarantine.event",
		EventVersion:   "1.0",
		Classification: "restricted-quarantine",
		Payload:        rawBytes,
	}
	p.topics[TopicQuarantine] = append(p.topics[TopicQuarantine], env)

	return &PublishResult{
		Topic:     TopicQuarantine,
		Partition: 0,
		Offset:    offset,
		Timestamp: time.Now().UTC(),
	}, nil
}

func (p *InMemKafkaPublisher) Close() error {
	return nil
}

func (p *InMemKafkaPublisher) GetMessages(topic string) []envelope.CanonicalEnvelope {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]envelope.CanonicalEnvelope(nil), p.topics[topic]...)
}
