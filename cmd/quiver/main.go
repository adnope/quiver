package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/adnope/quiver/internal/api"
	collectorNetflow "github.com/adnope/quiver/internal/collector/netflow"
	collectorZeek "github.com/adnope/quiver/internal/collector/zeek"
	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/observability"
	"github.com/adnope/quiver/internal/storage/postgres"
)

// @title Quiver API
// @version 0.1
// @description Network flow ingestion and query API. Protected endpoints use X-API-Key scopes: ingest, query, metrics.
// @BasePath /
// @schemes http https
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-API-Key
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
	flowRepo, err := postgres.NewFlowRepository(db)
	if err != nil {
		logger.ErrorContext(ctx, "create flow repository failed", slog.String("component", "cmd"), slog.Any("error", err))
		os.Exit(1)
	}
	stateStore, err := postgres.NewStateStore(db)
	if err != nil {
		logger.ErrorContext(ctx, "create collector state store failed", slog.String("component", "cmd"), slog.Any("error", err))
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

	apiServer, err := api.NewServerWithObservability(
		cfg,
		publisher,
		flowRepo,
		flowRepo,
		os.Getenv,
		metrics,
		api.StaticHealthChecker{Value: api.HealthOK},
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
	startCollectors(ctx, stop, cfg, stateStore, publisher, metrics, logger)

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
	cfg config.Config,
	stateStore postgres.CollectorStateStore,
	publisher kafka.RawEventPublisher,
	metrics *observability.Registry,
	logger *slog.Logger,
) {
	for _, collectorCfg := range cfg.Collectors.ZeekConnJSON {
		if !collectorCfg.Enabled {
			continue
		}
		collector, err := collectorZeek.NewCollector(collectorCfg, stateStore, publisher, metrics, logger)
		if err != nil {
			logger.ErrorContext(ctx, "create zeek collector failed", slog.String("component", "cmd"), slog.Any("error", err))
			stop()
			return
		}
		go func(id string) {
			if err := collector.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("zeek collector stopped", slog.String("component", "cmd"), slog.String("collector_id", id), slog.Any("error", err))
				stop()
			}
		}(collectorCfg.CollectorID)
	}
	for _, collectorCfg := range cfg.Collectors.NetFlowV5 {
		if !collectorCfg.Enabled {
			continue
		}
		collector, err := collectorNetflow.NewCollector(collectorCfg, cfg.DeadLetter.MaxRawPacketBytes, publisher, metrics, logger)
		if err != nil {
			logger.ErrorContext(ctx, "create netflow collector failed", slog.String("component", "cmd"), slog.Any("error", err))
			stop()
			return
		}
		go func(id string) {
			if err := collector.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("netflow collector stopped", slog.String("component", "cmd"), slog.String("collector_id", id), slog.Any("error", err))
				stop()
			}
		}(collectorCfg.CollectorID)
	}
}
