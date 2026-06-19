package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/adnope/quiver/internal/config"
)

const APIKeyHeader = "X-API-Key" // #nosec G101 -- header name, not a credential.

var (
	ErrMissingAPIKey     = errors.New("api: missing api key")
	ErrInvalidAPIKey     = errors.New("api: invalid api key")
	ErrInsufficientScope = errors.New("api: insufficient scope")
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

type principalContextKey struct{}

type Authenticator struct {
	keys []apiKey
}

type apiKey struct {
	value     string
	principal Principal
}

func NewAuthenticator(cfg config.Config, lookupEnv func(string) string) (*Authenticator, error) {
	if lookupEnv == nil {
		return nil, fmt.Errorf("api: env lookup is required")
	}
	merged := map[string]apiKey{}
	for _, item := range cfg.API.Keys {
		value := strings.TrimSpace(lookupEnv(item.KeyEnv))
		if value == "" {
			return nil, fmt.Errorf("api: key env %q is missing", item.KeyEnv)
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
			return nil, fmt.Errorf("api: rest key env %q is missing", item.KeyEnv)
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
			return nil, fmt.Errorf("api: client gateway key env %q is missing", item.KeyEnv)
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

func RequireScope(auth *Authenticator, limiter *RateLimiter, scope Scope, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.Authenticate(r.Header.Get(APIKeyHeader))
		if err != nil {
			if errors.Is(err, ErrMissingAPIKey) {
				writeError(w, r, http.StatusUnauthorized, CodeMissingAPIKey, "missing api key", nil)
				return
			}
			writeError(w, r, http.StatusUnauthorized, CodeInvalidAPIKey, "invalid api key", nil)
			return
		}
		if !principal.HasScope(scope) {
			writeError(w, r, http.StatusForbidden, CodeInsufficientScope, "api key lacks required scope", nil)
			return
		}
		if limiter != nil && !limiter.Allow(principal.Name, scope) {
			writeError(w, r, http.StatusTooManyRequests, CodeRateLimitExceeded, "rate limit exceeded", nil)
			return
		}
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

func (p Principal) HasScope(scope Scope) bool {
	if p.Scopes == nil {
		return false
	}
	_, ok := p.Scopes[scope]
	return ok
}

type RateLimiter struct {
	mu     sync.Mutex
	limits map[Scope]int
	now    func() time.Time
	state  map[string]rateState
}

type rateState struct {
	windowStart time.Time
	count       int
}

func NewRateLimiter(cfg config.RateLimitsConfig) *RateLimiter {
	return &RateLimiter{
		limits: map[Scope]int{
			ScopeIngest:  cfg.Ingest.RequestsPerMinute,
			ScopeQuery:   cfg.Query.RequestsPerMinute,
			ScopeMetrics: cfg.Metrics.RequestsPerMinute,
		},
		now:   time.Now,
		state: map[string]rateState{},
	}
}

func (l *RateLimiter) Allow(keyName string, scope Scope) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	limit := l.limits[scope]
	if limit <= 0 {
		return false
	}
	now := l.now()
	stateKey := keyName + ":" + string(scope)
	current := l.state[stateKey]
	if current.windowStart.IsZero() || now.Sub(current.windowStart) >= time.Minute {
		l.state[stateKey] = rateState{windowStart: now, count: 1}
		return true
	}
	if current.count >= limit {
		return false
	}
	current.count++
	l.state[stateKey] = current
	return true
}
