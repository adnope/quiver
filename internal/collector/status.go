package collector

import (
	"strings"
	"time"
)

type State string

const (
	StateOpened     State = "opened"
	StateRunning    State = "running"
	StateRestarting State = "restarting"
	StateStopped    State = "stopped"
	StateFailed     State = "failed"
)

type StatusSnapshot struct {
	CollectorID   string            `json:"collector_id"`
	Type          string            `json:"type"`
	SourceType    string            `json:"source_type"`
	Status        State             `json:"status"`
	RestartPolicy string            `json:"restart_policy"`
	RestartCount  int               `json:"restart_count"`
	LastStartedAt *time.Time        `json:"last_started_at,omitempty"`
	LastStoppedAt *time.Time        `json:"last_stopped_at,omitempty"`
	LastError     *string           `json:"last_error,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
}

func SanitizeError(err error) *string {
	if err == nil {
		return nil
	}
	return sanitizeText(err.Error())
}

func SanitizeDetails(details map[string]string) map[string]string {
	if len(details) == 0 {
		return nil
	}
	sanitized := make(map[string]string, len(details))
	for key, value := range details {
		cleanKey := sanitizeText(key)
		cleanValue := sanitizeText(value)
		if cleanKey == nil || cleanValue == nil {
			continue
		}
		sanitized[*cleanKey] = *cleanValue
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeText(raw string) *string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil
	}
	text = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		default:
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}
	}, text)
	text = strings.Join(strings.Fields(text), " ")
	const maxLen = 256
	if len(text) > maxLen {
		text = text[:maxLen]
	}
	if text == "" {
		return nil
	}
	return &text
}
