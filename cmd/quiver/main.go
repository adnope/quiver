package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/adnope/quiver/internal/api"
	collectorNetflow "github.com/adnope/quiver/internal/collector/netflow"
	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/ingest"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/observability"
	"github.com/adnope/quiver/internal/storage/postgres"
)

// @title Quiver API
// @version 0.1
// @description Network flow ingestion and query API. Protected endpoints use X-API-Key scopes: ingest, query, metrics. Generated output is Swagger 2.0.
// @BasePath /
// @schemes http https
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-API-Key
// @description API key with endpoint-specific scope. Ingest endpoints require ingest, query and aggregation endpoints require query, and metrics endpoints require metrics.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	configPath := flag.String("config", os.Getenv("QUIVER_CONFIG"), "path to Quiver YAML config")
	flag.Parse()
	if *configPath == "" {
		logger.ErrorContext(ctx, "missing config path", slog.String("component", "cmd"))
		os.Exit(1)
	}

	cfg, err := config.LoadFile(ctx, *configPath, os.Getenv)
	if err != nil {
		logger.ErrorContext(ctx, "load config failed", slog.String("component", "cmd"), slog.Any("error", err))
		os.Exit(1)
	}
	metrics := observability.NewRegistry()

	db, err := postgres.Open(ctx, cfg.Database)
	if err != nil {
		logger.ErrorContext(ctx, "open database failed", slog.String("component", "cmd"), slog.Any("error", err))
		os.Exit(1)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Warn("close database failed", slog.String("component", "cmd"), slog.Any("error", err))
		}
	}()

	metricsSaver := observability.NewMetricsSaver(db, metrics, logger, 10*time.Second)
	metricsSaver.Start(ctx)
	defer metricsSaver.Stop()

	if err := postgres.ApplyStoragePolicies(ctx, db, cfg.Storage); err != nil {
		logger.ErrorContext(ctx, "apply database storage policies failed", slog.String("component", "cmd"), slog.Any("error", err))
		os.Exit(1)
	}
	flowRepo, err := postgres.NewFlowRepository(db)
	if err != nil {
		logger.ErrorContext(ctx, "create flow repository failed", slog.String("component", "cmd"), slog.Any("error", err))
		os.Exit(1)
	}
	publisher, err := kafka.NewFranzPublisher(kafka.ConfigFromApp(cfg))
	if err != nil {
		logger.ErrorContext(ctx, "create kafka publisher failed", slog.String("component", "cmd"), slog.Any("error", err))
		os.Exit(1)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), cfg.Shutdown.Timeout.Std())
		defer cancel()
		if err := publisher.Close(closeCtx); err != nil {
			logger.Warn("close kafka publisher failed", slog.String("component", "cmd"), slog.Any("error", err))
		}
	}()

	storageWriter, err := postgres.NewStorageWriter(cfg.StorageWriter, flowRepo, publisher)
	if err != nil {
		logger.ErrorContext(ctx, "create storage writer failed", slog.String("component", "cmd"), slog.Any("error", err))
		os.Exit(1)
	}
	storageWriter = storageWriter.WithMetrics(metrics)

	pipeline, err := ingest.NewPipeline(cfg, storageWriter, publisher, metrics, logger)
	if err != nil {
		logger.ErrorContext(ctx, "create ingestion pipeline failed", slog.String("component", "cmd"), slog.Any("error", err))
		os.Exit(1)
	}
	pipeline.Start(ctx)
	defer pipeline.Stop()

	registry := newCollectorsRegistry()

	healthChecker := &api.CompositeHealthChecker{
		DB:              db,
		Publisher:       publisher,
		CollectorStatus: registry.Get,
	}

	var netflowCollectors []*collectorNetflow.Collector
	for _, collectorCfg := range cfg.Collectors.NetFlowV5 {
		if !collectorCfg.Enabled {
			continue
		}
		collector, err := collectorNetflow.NewCollector(collectorCfg, cfg.DeadLetter.MaxRawPacketBytes, publisher, metrics, logger)
		if err != nil {
			logger.ErrorContext(ctx, "create netflow collector failed", slog.String("component", "cmd"), slog.Any("error", err))
			os.Exit(1)
		}
		netflowCollectors = append(netflowCollectors, collector)
	}

	var injectableCollectors []api.InjectableCollector
	for _, c := range netflowCollectors {
		injectableCollectors = append(injectableCollectors, c)
	}

	apiServer, err := api.NewServerWithCollectors(
		cfg,
		publisher,
		flowRepo,
		flowRepo,
		os.Getenv,
		metrics,
		healthChecker,
		injectableCollectors,
	)
	if err != nil {
		logger.ErrorContext(ctx, "create api server failed", slog.String("component", "cmd"), slog.Any("error", err))
		os.Exit(1)
	}
	httpServer := &http.Server{
		Addr:              cfg.Server.HTTPAddr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.InfoContext(
		ctx,
		"quiver starting",
		slog.String("component", "cmd"),
		slog.String("http_addr", cfg.Server.HTTPAddr),
	)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server failed", slog.String("component", "cmd"), slog.Any("error", err))
			stop()
		}
	}()
	startCollectors(ctx, stop, logger, registry, netflowCollectors)

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Shutdown.Timeout.Std())
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("http shutdown failed", slog.String("component", "cmd"), slog.Any("error", err))
	}
	logger.Info("quiver stopped", slog.String("component", "cmd"))
}

func startCollectors(
	ctx context.Context,
	stop context.CancelFunc,
	logger *slog.Logger,
	registry *collectorsRegistry,
	netflowCollectors []*collectorNetflow.Collector,
) {
	for _, collector := range netflowCollectors {
		id := collector.CollectorID()
		registry.Set(id, "running")
		go func(c *collectorNetflow.Collector, cid string) {
			if err := c.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("netflow collector stopped", slog.String("component", "cmd"), slog.String("collector_id", cid), slog.Any("error", err))
				registry.Set(cid, "stopped")
				stop()
			}
		}(collector, id)
	}
}

type collectorsRegistry struct {
	mu     sync.Mutex
	status map[string]string
}

func newCollectorsRegistry() *collectorsRegistry {
	return &collectorsRegistry{
		status: make(map[string]string),
	}
}

func (r *collectorsRegistry) Set(id string, status string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status[id] = status
}

func (r *collectorsRegistry) Get() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := make(map[string]string, len(r.status))
	for k, v := range r.status {
		res[k] = v
	}
	return res
}
