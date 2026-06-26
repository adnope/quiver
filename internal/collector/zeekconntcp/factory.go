package zeekconntcp

import (
	"fmt"

	"github.com/adnope/quiver/internal/collector"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

const PluginType = "zeek_conn_tcp"

type Plugin struct{}

func NewPlugin() Plugin { return Plugin{} }

func (Plugin) Type() string { return PluginType }

func (Plugin) SettingsMode() collector.SettingsMode { return collector.SettingsRequired }

func (Plugin) SourceType() flowv1.SourceType {
	return flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON
}

func (Plugin) Build(ctx collector.BuildContext, cfg collector.InstanceConfig) (collector.RuntimeCollector, error) {
	settings, prefixes, err := decodeSettings(cfg)
	if err != nil {
		return nil, err
	}
	authenticator := ctx.Services.APIKeyAuthenticator
	if authenticator == nil {
		return nil, fmt.Errorf("build zeek_conn_tcp collector: authenticator is nil")
	}
	runtime, err := NewCollector(CollectorConfig{
		CollectorID:        cfg.CollectorID,
		Settings:           settings,
		AllowedPeerCIDRs:   prefixes,
		DeadLetterMaxBytes: ctx.DeadLetterMaxBytes,
	}, ctx.Publisher, authenticator, ctx.Metrics, ctx.Logger)
	if err != nil {
		return nil, fmt.Errorf("build zeek_conn_tcp collector: %w", err)
	}
	return runtime, nil
}
