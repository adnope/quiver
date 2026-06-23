package api

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/observability"
	"github.com/adnope/quiver/internal/web"
)

type Server struct {
	mux *http.ServeMux
}

func NewServer(cfg config.Config, publisher kafka.RawEventPublisher, lookupEnv func(string) string) (*Server, error) {
	return NewServerWithStores(cfg, publisher, nil, nil, lookupEnv)
}

func NewServerWithStores(
	cfg config.Config,
	publisher kafka.RawEventPublisher,
	flowStore FlowStore,
	aggregationStore AggregationStore,
	lookupEnv func(string) string,
) (*Server, error) {
	return NewServerWithObservability(
		cfg,
		publisher,
		flowStore,
		aggregationStore,
		lookupEnv,
		nil,
		StaticHealthChecker{Value: HealthOK},
	)
}

func NewServerWithObservability(
	cfg config.Config,
	publisher kafka.RawEventPublisher,
	flowStore FlowStore,
	aggregationStore AggregationStore,
	lookupEnv func(string) string,
	metrics *observability.Registry,
	health HealthChecker,
) (*Server, error) {
	return NewServerWithCollectors(
		cfg,
		publisher,
		flowStore,
		aggregationStore,
		lookupEnv,
		metrics,
		health,
		nil,
	)
}

func NewServerWithCollectors(
	cfg config.Config,
	publisher kafka.RawEventPublisher,
	flowStore FlowStore,
	aggregationStore AggregationStore,
	lookupEnv func(string) string,
	metrics *observability.Registry,
	health HealthChecker,
	netflowCollectors []InjectableCollector,
) (*Server, error) {
	auth, err := NewAuthenticator(cfg, lookupEnv)
	if err != nil {
		return nil, err
	}
	cursorCodec, err := cursorCodecFromConfig(cfg, lookupEnv)
	if err != nil {
		return nil, err
	}
	if (flowStore != nil || aggregationStore != nil) && cursorCodec == nil {
		return nil, ErrInvalidCursor
	}
	limiter := NewRateLimiter(cfg.API.RateLimits)
	mux := http.NewServeMux()
	ingestHandler := NewIngestHandler(cfg, publisher)
	mux.Handle(
		"POST /api/v1/ingest/flows",
		route(metrics, "POST /api/v1/ingest/flows", RequestIDMiddleware(RequireScope(auth, limiter, ScopeIngest, ingestHandler))),
	)
	if cfg.ZeekIngest.Enabled {
		zeekIngestHandler := NewZeekConnIngestHandler(cfg, publisher)
		mux.Handle(
			"POST /api/v1/ingest/zeek/conn",
			route(metrics, "POST /api/v1/ingest/zeek/conn", RequestIDMiddleware(RequireScope(auth, limiter, ScopeIngest, zeekIngestHandler))),
		)
	}
	proxyHandler := NewProxyHandler(cfg, netflowCollectors)
	mux.Handle(
		"POST /api/v1/ingest/proxy-netflow",
		route(metrics, "POST /api/v1/ingest/proxy-netflow", RequestIDMiddleware(RequireScope(auth, limiter, ScopeIngest, proxyHandler))),
	)
	queryHandler := NewQueryHandler(cfg, flowStore, cursorCodec)
	mux.Handle(
		"GET /api/v1/flows",
		route(metrics, "GET /api/v1/flows", RequestIDMiddleware(RequireScope(auth, limiter, ScopeQuery, http.HandlerFunc(queryHandler.Search)))),
	)
	mux.Handle(
		"GET /api/v1/flows/",
		route(metrics, "GET /api/v1/flows/{id}", RequestIDMiddleware(RequireScope(auth, limiter, ScopeQuery, http.HandlerFunc(queryHandler.Lookup)))),
	)
	aggregationHandler := NewAggregationHandler(cfg, aggregationStore, cursorCodec)
	mux.Handle(
		"GET /api/v1/aggregations/top-talkers",
		route(metrics, "GET /api/v1/aggregations/top-talkers", RequestIDMiddleware(RequireScope(auth, limiter, ScopeQuery, http.HandlerFunc(aggregationHandler.TopTalkers)))),
	)
	mux.Handle(
		"GET /api/v1/aggregations/top-ports",
		route(metrics, "GET /api/v1/aggregations/top-ports", RequestIDMiddleware(RequireScope(auth, limiter, ScopeQuery, http.HandlerFunc(aggregationHandler.TopPorts)))),
	)
	mux.Handle(
		"GET /api/v1/aggregations/protocols",
		route(metrics, "GET /api/v1/aggregations/protocols", RequestIDMiddleware(RequireScope(auth, limiter, ScopeQuery, http.HandlerFunc(aggregationHandler.Protocols)))),
	)
	healthHandler := HealthHandler(health, auth)
	if cfg.API.Health.AuthRequired {
		healthHandler = RequestIDMiddleware(RequireScope(auth, limiter, ScopeMetrics, healthHandler))
	}
	mux.Handle("GET /health", route(metrics, "GET /health", healthHandler))
	metricsHandler := MetricsHandler(metrics)
	if cfg.API.Metrics.AuthRequired {
		metricsHandler = RequestIDMiddleware(RequireScope(auth, limiter, ScopeMetrics, metricsHandler))
	}
	mux.Handle("GET /metrics", route(metrics, "GET /metrics", metricsHandler))

	var db *sql.DB
	if provider, ok := flowStore.(interface{ DB() *sql.DB }); ok {
		db = provider.DB()
	}

	liveHandler := LiveMetricsHandler(metrics)
	historyHandler := MetricsHistoryHandler(db)
	if cfg.API.Metrics.AuthRequired {
		liveHandler = RequestIDMiddleware(RequireScope(auth, limiter, ScopeMetrics, liveHandler))
		historyHandler = RequestIDMiddleware(RequireScope(auth, limiter, ScopeMetrics, historyHandler))
	}
	mux.Handle("GET /api/v1/metrics/live", route(metrics, "GET /api/v1/metrics/live", liveHandler))
	mux.Handle("GET /api/v1/metrics/history", route(metrics, "GET /api/v1/metrics/history", historyHandler))
	mux.Handle("GET /", route(metrics, "GET /", FrontendHandler(web.DistFS())))

	return &Server{mux: mux}, nil

}

func (s *Server) Handler() http.Handler {
	if s == nil || s.mux == nil {
		return http.NotFoundHandler()
	}
	return s.mux
}

func cursorCodecFromConfig(cfg config.Config, lookupEnv func(string) string) (*CursorCodec, error) {
	if lookupEnv == nil {
		return nil, nil
	}
	envName := strings.TrimSpace(cfg.API.Cursor.HMACSecretEnv)
	if envName == "" {
		return nil, nil
	}
	secret := strings.TrimSpace(lookupEnv(envName))
	if secret == "" {
		return nil, nil
	}
	return NewCursorCodec(secret)
}

func route(metrics *observability.Registry, route string, handler http.Handler) http.Handler {
	return instrumentHTTP(metrics, route, handler)
}
