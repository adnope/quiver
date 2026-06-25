package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/adnope/quiver/internal/api"
	"github.com/adnope/quiver/internal/collector"
	"github.com/adnope/quiver/internal/collector/builtin"
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

	metricsSaver := observability.NewMetricsSaverWithBucketWidth(
		db,
		metrics,
		logger,
		cfg.Observability.MetricsSaveInterval.Std(),
		cfg.Observability.MetricsAggregateBucketWidth.Std(),
	)
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

	builtinRegistry, err := builtin.NewRegistry()
	if err != nil {
		logger.ErrorContext(ctx, "create collector registry failed", slog.String("component", "cmd"), slog.Any("error", err))
		os.Exit(1)
	}

	collectorManager, err := collector.NewManager(ctx, builtinRegistry, cfg.Collectors, collector.BuildContext{
		Publisher:          publisher,
		Metrics:            metrics,
		Logger:             logger,
		DeadLetterMaxBytes: cfg.DeadLetter.MaxRawPacketBytes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "create collector manager failed", slog.String("component", "cmd"), slog.Any("error", err))
		os.Exit(1)
	}

	var proxyTarget api.InjectableCollector
	if len(cfg.QuiverClientGateways) > 0 {
		targetID := cfg.ProxyNetFlow.CollectorID
		target, ok := collectorManager.PacketCollector(targetID)
		if !ok {
			err := proxyTargetError(collectorManager, targetID)
			logger.ErrorContext(ctx, "secure proxy target unavailable", slog.String("component", "cmd"), slog.String("collector_id", targetID), slog.Any("error", err))
			os.Exit(1)
		}
		proxyTarget = target
	}

	healthChecker := &api.CompositeHealthChecker{
		DB:                 db,
		Publisher:          publisher,
		CollectorSnapshots: collectorManager.StatusSnapshots,
	}

	apiServer, err := api.NewServerWithCollectors(
		cfg,
		publisher,
		flowRepo,
		flowRepo,
		os.Getenv,
		metrics,
		healthChecker,
		proxyTarget,
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
	collectorManager.Start(ctx)
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), cfg.Shutdown.Timeout.Std())
		defer cancel()
		collectorManager.Stop(stopCtx)
	}()
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server failed", slog.String("component", "cmd"), slog.Any("error", err))
			stop()
		}
	}()

	aggregateRefresher := postgres.NewFlowAggregateRefresher(db, logger)
	go aggregateRefresher.Run(ctx)

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Shutdown.Timeout.Std())
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("http shutdown failed", slog.String("component", "cmd"), slog.Any("error", err))
	}
	logger.Info("quiver stopped", slog.String("component", "cmd"))
}

func proxyTargetError(manager *collector.Manager, collectorID string) error {
	if manager.CollectorExists(collectorID) {
		return fmt.Errorf("collector %q does not implement packet collector", collectorID)
	}
	return fmt.Errorf("collector %q does not exist", collectorID)
}
