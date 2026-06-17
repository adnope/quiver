package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/adnope/quiver/internal/domain"
)

const RequestIDHeader = "X-Request-ID"

type requestIDContextKey struct{}

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get(RequestIDHeader))
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set(RequestIDHeader, requestID)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

func newRequestID() string {
	id, err := domain.NewUUIDv7(time.Now())
	if err == nil {
		return "req_" + id
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req_unavailable"
	}
	return "req_" + hex.EncodeToString(b[:])
}
