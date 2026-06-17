package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/adnope/quiver/internal/domain"
	"github.com/adnope/quiver/internal/storage/postgres"
)

var ErrInvalidCursor = errors.New("api: invalid cursor")

type CursorCodec struct {
	secret []byte
}

type cursorPayload struct {
	Version        int    `json:"v"`
	EventStartTime string `json:"event_start_time"`
	ID             string `json:"id"`
}

type cursorToken struct {
	Payload   cursorPayload `json:"payload"`
	Signature string        `json:"sig"`
}

func NewCursorCodec(secret string) (*CursorCodec, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("%w: hmac secret must be at least 32 bytes", ErrInvalidCursor)
	}
	return &CursorCodec{secret: []byte(secret)}, nil
}

func (c *CursorCodec) Encode(cursor postgres.FlowCursor) (string, error) {
	if c == nil || len(c.secret) == 0 {
		return "", fmt.Errorf("%w: codec is not initialized", ErrInvalidCursor)
	}
	if cursor.EventStartTime.IsZero() || !domain.IsUUIDv7(cursor.ID) {
		return "", fmt.Errorf("%w: payload is invalid", ErrInvalidCursor)
	}
	payload := cursorPayload{
		Version:        1,
		EventStartTime: cursor.EventStartTime.UTC().Format(time.RFC3339Nano),
		ID:             cursor.ID,
	}
	signature, err := c.sign(payload)
	if err != nil {
		return "", err
	}
	token := cursorToken{Payload: payload, Signature: signature}
	data, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("marshal cursor token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func (c *CursorCodec) Decode(value string) (postgres.FlowCursor, error) {
	if c == nil || len(c.secret) == 0 {
		return postgres.FlowCursor{}, fmt.Errorf("%w: codec is not initialized", ErrInvalidCursor)
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return postgres.FlowCursor{}, fmt.Errorf("%w: decode base64", ErrInvalidCursor)
	}
	var token cursorToken
	if err := json.Unmarshal(data, &token); err != nil {
		return postgres.FlowCursor{}, fmt.Errorf("%w: decode json", ErrInvalidCursor)
	}
	if token.Payload.Version != 1 {
		return postgres.FlowCursor{}, fmt.Errorf("%w: unsupported version", ErrInvalidCursor)
	}
	expected, err := c.sign(token.Payload)
	if err != nil {
		return postgres.FlowCursor{}, err
	}
	if !hmac.Equal([]byte(expected), []byte(token.Signature)) {
		return postgres.FlowCursor{}, fmt.Errorf("%w: signature mismatch", ErrInvalidCursor)
	}
	eventStartTime, err := time.Parse(time.RFC3339Nano, token.Payload.EventStartTime)
	if err != nil {
		return postgres.FlowCursor{}, fmt.Errorf("%w: invalid event_start_time", ErrInvalidCursor)
	}
	if !domain.IsUUIDv7(token.Payload.ID) {
		return postgres.FlowCursor{}, fmt.Errorf("%w: invalid id", ErrInvalidCursor)
	}
	return postgres.FlowCursor{EventStartTime: eventStartTime.UTC(), ID: token.Payload.ID}, nil
}

func (c *CursorCodec) sign(payload cursorPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal cursor payload: %w", err)
	}
	mac := hmac.New(sha256.New, c.secret)
	if _, err := mac.Write(data); err != nil {
		return "", fmt.Errorf("sign cursor payload: %w", err)
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}
