package netflow

import (
	"fmt"

	"github.com/adnope/quiver/internal/collector"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

const PluginType = "netflow_v5"

type Plugin struct{}

func NewPlugin() Plugin { return Plugin{} }

func (Plugin) Type() string { return PluginType }

func (Plugin) SettingsMode() collector.SettingsMode { return collector.SettingsRequired }

func (Plugin) Build(ctx collector.BuildContext, cfg collector.InstanceConfig) (collector.RuntimeCollector, error) {
	settings, err := decodeConfig(cfg)
	if err != nil {
		return nil, err
	}
	runtimeCollector, err := NewCollector(CollectorConfig{
		CollectorID:       cfg.CollectorID,
		ListenAddr:        settings.ListenAddr,
		ReadBufferBytes:   settings.ReadBufferBytes,
		PacketBufferBytes: settings.PacketBufferBytes,
		AuthRequired:      settings.AuthRequired,
	}, ctx.DeadLetterMaxBytes, ctx.Publisher, ctx.Metrics, ctx.Logger)
	if err != nil {
		return nil, fmt.Errorf("build netflow v5 collector: %w", err)
	}
	return runtimeCollector, nil
}

func (Plugin) SourceType() flowv1.SourceType { return flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5 }
