package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	quiverauth "github.com/adnope/quiver/internal/auth"
	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/observability"
)

var (
	ErrMissingAPIKey     = quiverauth.ErrMissingAPIKey
	ErrInvalidAPIKey     = quiverauth.ErrInvalidAPIKey
	ErrInsufficientScope = quiverauth.ErrInsufficientScope
)

const APIKeyHeader = quiverauth.APIKeyHeader

const (
	ScopeIngest  = quiverauth.ScopeIngest
	ScopeQuery   = quiverauth.ScopeQuery
	ScopeMetrics = quiverauth.ScopeMetrics
)

type (
	Scope         = quiverauth.Scope
	Principal     = quiverauth.Principal
	Authenticator = quiverauth.Authenticator
)

type principalContextKey struct{}

func NewAuthenticator(cfg config.Config, lookupEnv func(string) string) (*Authenticator, error) {
	return quiverauth.NewAuthenticator(cfg, lookupEnv)
}

func RequireScope(auth *Authenticator, limiter *RateLimiter, metrics *observability.Registry, scope Scope, next http.Handler) http.Handler {
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
			if metrics != nil {
				metrics.Inc("rate_limit_rejections_total", map[string]string{
					"key":   principal.Name,
					"scope": string(scope),
				})
			}
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
