package collector

import (
	"context"
	"log/slog"
	"net/netip"

	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/observability"
)

type Plugin interface {
	Type() string
	SettingsMode() SettingsMode
	Build(ctx BuildContext, cfg InstanceConfig) (RuntimeCollector, error)
}

type RuntimeCollector interface {
	ID() string
	Type() string
	SourceType() flowv1.SourceType
	Open(ctx context.Context) error
	Run(ctx context.Context) error
	Close(ctx context.Context) error
	Health(ctx context.Context) CollectorHealth
}

type PacketCollector interface {
	RuntimeCollector
	HandlePacket(ctx context.Context, sourceIP netip.Addr, sourceHost string, data []byte) error
}

type CollectorHealth struct {
	Details map[string]string
}

type BuildContext struct {
	Publisher          kafka.RawEventPublisher
	Metrics            *observability.Registry
	Logger             *slog.Logger
	DeadLetterMaxBytes int
}
