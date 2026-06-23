package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/adnope/quiver/internal/domain"
	"github.com/adnope/quiver/internal/storage/postgres"
)

var ErrInvalidCursor = errors.New("api: invalid cursor")

const aggregationCursorKind = "aggregation"

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

type aggregationCursorPayload struct {
	Version           int     `json:"v"`
	Kind              string  `json:"kind"`
	Endpoint          string  `json:"endpoint"`
	QueryHash         string  `json:"query_hash"`
	Metric            string  `json:"metric"`
	Direction         string  `json:"direction,omitempty"`
	Value             uint64  `json:"value"`
	FlowCount         uint64  `json:"flow_count"`
	IP                string  `json:"ip,omitempty"`
	Port              *uint16 `json:"port,omitempty"`
	ProtocolNumber    *uint8  `json:"protocol_number,omitempty"`
	TransportProtocol string  `json:"transport_protocol,omitempty"`
}

type aggregationCursorToken struct {
	Payload   aggregationCursorPayload `json:"payload"`
	Signature string                   `json:"sig"`
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

func (c *CursorCodec) EncodeAggregation(cursor postgres.AggregationCursor) (string, error) {
	if c == nil || len(c.secret) == 0 {
		return "", fmt.Errorf("%w: codec is not initialized", ErrInvalidCursor)
	}
	payload, err := aggregationCursorToPayload(cursor)
	if err != nil {
		return "", err
	}
	signature, err := c.sign(payload)
	if err != nil {
		return "", err
	}
	token := aggregationCursorToken{Payload: payload, Signature: signature}
	data, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("marshal aggregation cursor token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func (c *CursorCodec) DecodeAggregation(value string) (postgres.AggregationCursor, error) {
	if c == nil || len(c.secret) == 0 {
		return postgres.AggregationCursor{}, fmt.Errorf("%w: codec is not initialized", ErrInvalidCursor)
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return postgres.AggregationCursor{}, fmt.Errorf("%w: decode base64", ErrInvalidCursor)
	}
	var token aggregationCursorToken
	if err := json.Unmarshal(data, &token); err != nil {
		return postgres.AggregationCursor{}, fmt.Errorf("%w: decode json", ErrInvalidCursor)
	}
	if token.Payload.Version != 1 {
		return postgres.AggregationCursor{}, fmt.Errorf("%w: unsupported version", ErrInvalidCursor)
	}
	if token.Payload.Kind != aggregationCursorKind {
		return postgres.AggregationCursor{}, fmt.Errorf("%w: unsupported kind", ErrInvalidCursor)
	}
	expected, err := c.sign(token.Payload)
	if err != nil {
		return postgres.AggregationCursor{}, err
	}
	if !hmac.Equal([]byte(expected), []byte(token.Signature)) {
		return postgres.AggregationCursor{}, fmt.Errorf("%w: signature mismatch", ErrInvalidCursor)
	}
	return aggregationCursorFromPayload(token.Payload)
}

func aggregationCursorToPayload(cursor postgres.AggregationCursor) (aggregationCursorPayload, error) {
	payload := aggregationCursorPayload{
		Version:           1,
		Kind:              aggregationCursorKind,
		Endpoint:          string(cursor.Endpoint),
		QueryHash:         cursor.QueryHash,
		Metric:            string(cursor.Metric),
		Direction:         string(cursor.Direction),
		Value:             cursor.Value,
		FlowCount:         cursor.FlowCount,
		Port:              cursor.Port,
		ProtocolNumber:    cursor.ProtocolNumber,
		TransportProtocol: transportProtocolString(cursor.TransportProtocol),
	}
	if cursor.QueryHash == "" {
		return aggregationCursorPayload{}, fmt.Errorf("%w: query_hash is required", ErrInvalidCursor)
	}
	switch cursor.Endpoint {
	case postgres.AggregationEndpointTopTalkers:
		if cursor.IP == nil {
			return aggregationCursorPayload{}, fmt.Errorf("%w: ip is required", ErrInvalidCursor)
		}
		payload.IP = cursor.IP.String()
	case postgres.AggregationEndpointTopPorts:
		if cursor.Port == nil {
			return aggregationCursorPayload{}, fmt.Errorf("%w: port is required", ErrInvalidCursor)
		}
	case postgres.AggregationEndpointProtocols:
		if cursor.ProtocolNumber == nil || cursor.TransportProtocol == nil {
			return aggregationCursorPayload{}, fmt.Errorf("%w: protocol key is required", ErrInvalidCursor)
		}
	default:
		return aggregationCursorPayload{}, fmt.Errorf("%w: endpoint is invalid", ErrInvalidCursor)
	}
	switch cursor.Metric {
	case postgres.AggregationMetricBytes, postgres.AggregationMetricPackets, postgres.AggregationMetricFlows:
	default:
		return aggregationCursorPayload{}, fmt.Errorf("%w: metric is invalid", ErrInvalidCursor)
	}
	if cursor.Endpoint != postgres.AggregationEndpointProtocols && cursor.Direction != postgres.AggregationDirectionSrc && cursor.Direction != postgres.AggregationDirectionDst {
		return aggregationCursorPayload{}, fmt.Errorf("%w: direction is invalid", ErrInvalidCursor)
	}
	return payload, nil
}

func aggregationCursorFromPayload(payload aggregationCursorPayload) (postgres.AggregationCursor, error) {
	cursor := postgres.AggregationCursor{
		Endpoint:  postgres.AggregationEndpoint(payload.Endpoint),
		QueryHash: payload.QueryHash,
		Metric:    postgres.AggregationMetric(payload.Metric),
		Direction: postgres.AggregationDirection(payload.Direction),
		Value:     payload.Value,
		FlowCount: payload.FlowCount,
	}
	if cursor.QueryHash == "" {
		return postgres.AggregationCursor{}, fmt.Errorf("%w: query_hash is required", ErrInvalidCursor)
	}
	switch cursor.Metric {
	case postgres.AggregationMetricBytes, postgres.AggregationMetricPackets, postgres.AggregationMetricFlows:
	default:
		return postgres.AggregationCursor{}, fmt.Errorf("%w: metric is invalid", ErrInvalidCursor)
	}
	switch cursor.Endpoint {
	case postgres.AggregationEndpointTopTalkers:
		ip, err := netip.ParseAddr(payload.IP)
		if err != nil {
			return postgres.AggregationCursor{}, fmt.Errorf("%w: ip is invalid", ErrInvalidCursor)
		}
		cursor.IP = &ip
	case postgres.AggregationEndpointTopPorts:
		if payload.Port == nil {
			return postgres.AggregationCursor{}, fmt.Errorf("%w: port is required", ErrInvalidCursor)
		}
		cursor.Port = payload.Port
	case postgres.AggregationEndpointProtocols:
		if payload.ProtocolNumber == nil || payload.TransportProtocol == "" {
			return postgres.AggregationCursor{}, fmt.Errorf("%w: protocol key is required", ErrInvalidCursor)
		}
		transportProtocol := domain.TransportProtocol(payload.TransportProtocol)
		cursor.ProtocolNumber = payload.ProtocolNumber
		cursor.TransportProtocol = &transportProtocol
	default:
		return postgres.AggregationCursor{}, fmt.Errorf("%w: endpoint is invalid", ErrInvalidCursor)
	}
	if cursor.Endpoint != postgres.AggregationEndpointProtocols && cursor.Direction != postgres.AggregationDirectionSrc && cursor.Direction != postgres.AggregationDirectionDst {
		return postgres.AggregationCursor{}, fmt.Errorf("%w: direction is invalid", ErrInvalidCursor)
	}
	return cursor, nil
}

func transportProtocolString(protocol *domain.TransportProtocol) string {
	if protocol == nil {
		return ""
	}
	return string(*protocol)
}

func (c *CursorCodec) sign(payload any) (string, error) {
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
