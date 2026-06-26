package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/adnope/quiver/internal/config"
)

const APIKeyHeader = "X-API-Key" // #nosec G101 -- header name, not a credential.

var (
	ErrMissingAPIKey     = errors.New("auth: missing api key")
	ErrInvalidAPIKey     = errors.New("auth: invalid api key")
	ErrInsufficientScope = errors.New("auth: insufficient scope")
)

type Scope string

const (
	ScopeIngest  Scope = "ingest"
	ScopeQuery   Scope = "query"
	ScopeMetrics Scope = "metrics"
)

type Principal struct {
	Name       string
	Scopes     map[Scope]struct{}
	SourceHost string
}

type APIKeyAuthenticator interface {
	Authenticate(value string) (Principal, error)
}

type Authenticator struct {
	keys []apiKey
}

type apiKey struct {
	value     string
	principal Principal
}

func NewAuthenticator(cfg config.Config, lookupEnv func(string) string) (*Authenticator, error) {
	if lookupEnv == nil {
		return nil, fmt.Errorf("auth: env lookup is required")
	}
	merged := map[string]apiKey{}
	for _, item := range cfg.API.Keys {
		value := strings.TrimSpace(lookupEnv(item.KeyEnv))
		if value == "" {
			return nil, fmt.Errorf("auth: key env %q is missing", item.KeyEnv)
		}
		key := merged[value]
		key.value = value
		key.principal.Name = item.Name
		if key.principal.Scopes == nil {
			key.principal.Scopes = map[Scope]struct{}{}
		}
		for _, scope := range item.Scopes {
			key.principal.Scopes[Scope(scope)] = struct{}{}
		}
		merged[value] = key
	}
	for _, item := range cfg.RestIngest.APIKeys {
		value := strings.TrimSpace(lookupEnv(item.KeyEnv))
		if value == "" {
			return nil, fmt.Errorf("auth: rest key env %q is missing", item.KeyEnv)
		}
		key := merged[value]
		key.value = value
		if key.principal.Name == "" {
			key.principal.Name = item.Name
		}
		if key.principal.Scopes == nil {
			key.principal.Scopes = map[Scope]struct{}{}
		}
		key.principal.Scopes[ScopeIngest] = struct{}{}
		key.principal.SourceHost = item.SourceHost
		merged[value] = key
	}
	for _, item := range cfg.QuiverClientGateways {
		value := strings.TrimSpace(lookupEnv(item.KeyEnv))
		if value == "" {
			return nil, fmt.Errorf("auth: client gateway key env %q is missing", item.KeyEnv)
		}
		key := merged[value]
		key.value = value
		if key.principal.Name == "" {
			key.principal.Name = item.Name
		}
		if key.principal.Scopes == nil {
			key.principal.Scopes = map[Scope]struct{}{}
		}
		key.principal.Scopes[ScopeIngest] = struct{}{}
		key.principal.SourceHost = item.SourceHost
		merged[value] = key
	}

	keys := make([]apiKey, 0, len(merged))
	for _, key := range merged {
		keys = append(keys, key)
	}
	return &Authenticator{keys: keys}, nil
}

func (a *Authenticator) Authenticate(value string) (Principal, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Principal{}, ErrMissingAPIKey
	}
	if a == nil {
		return Principal{}, ErrInvalidAPIKey
	}
	for _, key := range a.keys {
		if subtle.ConstantTimeCompare([]byte(value), []byte(key.value)) == 1 {
			return key.principal, nil
		}
	}
	return Principal{}, ErrInvalidAPIKey
}

func (p Principal) HasScope(scope Scope) bool {
	if p.Scopes == nil {
		return false
	}
	_, ok := p.Scopes[scope]
	return ok
}
