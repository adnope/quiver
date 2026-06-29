package netflowv9

import (
	"fmt"
	"time"

	"github.com/adnope/quiver/internal/collector"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

type Plugin struct{}

func NewPlugin() Plugin { return Plugin{} }

func (Plugin) Type() string { return PluginType }

func (Plugin) SettingsMode() collector.SettingsMode { return collector.SettingsRequired }

func (Plugin) SourceType() flowv1.SourceType { return flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9 }

func (Plugin) Build(ctx collector.BuildContext, cfg collector.InstanceConfig) (collector.RuntimeCollector, error) {
	settings, err := decodeSettings(cfg)
	if err != nil {
		return nil, fmt.Errorf("build netflow v9 collector: %w", err)
	}
	return NewCollector(cfg.CollectorID, settings, ctx)
}

type PendingSettings struct {
	MaxWait             time.Duration `yaml:"max_wait"`
	MaxBytesPerExporter int           `yaml:"max_bytes_per_exporter"`
	MaxBytesTotal       int           `yaml:"max_bytes_total"`
}

type CollectorSettings struct {
	TemplateTTL             time.Duration   `yaml:"template_ttl"`
	CleanupInterval         time.Duration   `yaml:"cleanup_interval"`
	ExporterIdleTimeout     time.Duration   `yaml:"exporter_idle_timeout"`
	SamplingRate            uint32          `yaml:"sampling_rate"`
	MaxPacketBytes          int             `yaml:"max_packet_bytes"`
	MaxExporters            int             `yaml:"max_exporters"`
	MaxTemplatesPerExporter int             `yaml:"max_templates_per_exporter"`
	MaxTemplatesTotal       int             `yaml:"max_templates_total"`
	MaxFieldsPerTemplate    int             `yaml:"max_fields_per_template"`
	MaxRecordBytes          int             `yaml:"max_record_bytes"`
	MaxUnknownFieldBytes    int             `yaml:"max_unknown_field_bytes"`
	MaxAttributesBytes      int             `yaml:"max_attributes_bytes"`
	WorkerCount             int             `yaml:"worker_count"`
	QueueCapacity           int             `yaml:"queue_capacity"`
	MaxQueueBytes           int             `yaml:"max_queue_bytes"`
	Pending                 PendingSettings `yaml:"pending"`
}

func decodeSettings(cfg collector.InstanceConfig) (CollectorSettings, error) {
	var settings CollectorSettings
	if err := collector.DecodeSettingsStrict(collector.SettingsRequired, cfg.Settings, &settings); err != nil {
		return CollectorSettings{}, err
	}
	if settings.TemplateTTL <= 0 || settings.CleanupInterval <= 0 || settings.ExporterIdleTimeout <= 0 || settings.Pending.MaxWait <= 0 {
		return CollectorSettings{}, fmt.Errorf("%w: all durations must be positive", ErrConfig)
	}
	if settings.CleanupInterval >= settings.TemplateTTL {
		return CollectorSettings{}, fmt.Errorf("%w: cleanup_interval must be less than template_ttl", ErrConfig)
	}
	if settings.MaxPacketBytes <= 0 || settings.MaxExporters <= 0 || settings.MaxTemplatesPerExporter <= 0 ||
		settings.MaxTemplatesTotal <= 0 || settings.MaxFieldsPerTemplate <= 0 || settings.MaxRecordBytes <= 0 ||
		settings.MaxUnknownFieldBytes <= 0 || settings.MaxAttributesBytes <= 0 || settings.QueueCapacity <= 0 ||
		settings.MaxQueueBytes <= 0 || settings.Pending.MaxBytesPerExporter <= 0 || settings.Pending.MaxBytesTotal <= 0 {
		return CollectorSettings{}, fmt.Errorf("%w: all limits must be positive", ErrConfig)
	}
	if settings.WorkerCount < 0 {
		return CollectorSettings{}, fmt.Errorf("%w: worker_count must be non-negative", ErrConfig)
	}
	if settings.SamplingRate <= 0 {
		return CollectorSettings{}, fmt.Errorf("%w: sampling_rate must be positive", ErrConfig)
	}
	if settings.Pending.MaxBytesPerExporter > settings.Pending.MaxBytesTotal {
		return CollectorSettings{}, fmt.Errorf("%w: pending max_bytes_per_exporter must not exceed max_bytes_total", ErrConfig)
	}
	return settings, nil
}
