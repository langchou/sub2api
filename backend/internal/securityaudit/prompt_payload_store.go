package securityaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const promptPayloadFormat = "sub2api-prompt-audit-v2"

type queuedPromptPayload struct {
	Format       string `json:"format"`
	DecisionText string `json:"decision_text"`
	FullPrompt   string `json:"full_prompt"`
}

func encodePromptPayload(snapshot PromptSnapshot) (string, error) {
	if snapshot.DecisionText == "" || snapshot.FullPrompt == "" {
		return "", fmt.Errorf("prompt audit payload input invalid")
	}
	raw, err := json.Marshal(queuedPromptPayload{
		Format: promptPayloadFormat, DecisionText: snapshot.DecisionText, FullPrompt: snapshot.FullPrompt,
	})
	return string(raw), err
}

func decodePromptPayload(raw string) (queuedPromptPayload, error) {
	if raw == "" {
		return queuedPromptPayload{}, fmt.Errorf("prompt audit payload input invalid")
	}
	var payload queuedPromptPayload
	if err := json.Unmarshal([]byte(raw), &payload); err == nil && payload.Format == promptPayloadFormat {
		if payload.DecisionText == "" || payload.FullPrompt == "" {
			return queuedPromptPayload{}, fmt.Errorf("prompt audit payload input invalid")
		}
		return payload, nil
	}
	// Jobs queued by the previous release contain the full scan text directly.
	decisionText, _, _ := strings.Cut(raw, promptAuditPrioritySeparator)
	return queuedPromptPayload{Format: "legacy", DecisionText: decisionText, FullPrompt: FullPromptFromScanText(raw)}, nil
}

type PayloadStore interface {
	Set(ctx context.Context, jobID int64, scanText string, ttl time.Duration) error
	Get(ctx context.Context, jobID int64) (string, error)
	Delete(ctx context.Context, jobID int64) error
	Ping(ctx context.Context) error
}

type RedisPayloadStore struct {
	client *redis.Client
}

func NewRedisPayloadStore(client *redis.Client) *RedisPayloadStore {
	return &RedisPayloadStore{client: client}
}

func (s *RedisPayloadStore) Set(ctx context.Context, jobID int64, scanText string, ttl time.Duration) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("prompt audit payload store unavailable")
	}
	if jobID <= 0 || scanText == "" {
		return fmt.Errorf("prompt audit payload input invalid")
	}
	if ttl <= 0 || ttl > DefaultPayloadTTL {
		ttl = DefaultPayloadTTL
	}
	return s.client.Set(ctx, payloadKey(jobID), scanText, ttl).Err()
}

func (s *RedisPayloadStore) Get(ctx context.Context, jobID int64) (string, error) {
	if s == nil || s.client == nil {
		return "", fmt.Errorf("prompt audit payload store unavailable")
	}
	return s.client.Get(ctx, payloadKey(jobID)).Result()
}

func (s *RedisPayloadStore) Delete(ctx context.Context, jobID int64) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("prompt audit payload store unavailable")
	}
	return s.client.Del(ctx, payloadKey(jobID)).Err()
}

func (s *RedisPayloadStore) Ping(ctx context.Context) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("prompt audit payload store unavailable")
	}
	return s.client.Ping(ctx).Err()
}

func payloadKey(jobID int64) string {
	return PayloadKeyPrefix + strconv.FormatInt(jobID, 10)
}
