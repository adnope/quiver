package netflowv9

import (
	"errors"
	"fmt"
	"time"
)

const PluginType = "netflow_v9"

const (
	DefaultTemplateTTL             = time.Hour
	DefaultExporterIdleTimeout     = 24 * time.Hour
	DefaultCleanupInterval         = time.Minute
	DefaultMaxExporters            = 4096
	DefaultMaxTemplatesPerExporter = 1024
	DefaultMaxTemplatesTotal       = 65536
	DefaultMaxFieldsPerTemplate    = 128
	DefaultMaxRecordBytes          = 65535
	DefaultMaxPacketBytes          = 65535
	DefaultPendingMaxWait          = 30 * time.Second
	DefaultPendingBytesPerExporter = 1 << 20
	DefaultPendingBytesTotal       = 32 << 20
)

var ErrConfig = errors.New("netflow v9 config")

type Config struct {
	TemplateTTL             time.Duration
	ExporterIdleTimeout     time.Duration
	CleanupInterval         time.Duration
	MaxExporters            int
	MaxTemplatesPerExporter int
	MaxTemplatesTotal       int
	MaxFieldsPerTemplate    int
	MaxRecordBytes          int
	MaxPacketBytes          int
	PendingMaxWait          time.Duration
	PendingBytesPerExporter int
	PendingBytesTotal       int
}

func (c Config) withDefaults() Config {
	if c.TemplateTTL == 0 {
		c.TemplateTTL = DefaultTemplateTTL
	}
	if c.ExporterIdleTimeout == 0 {
		c.ExporterIdleTimeout = DefaultExporterIdleTimeout
	}
	if c.CleanupInterval == 0 {
		c.CleanupInterval = DefaultCleanupInterval
	}
	if c.MaxExporters == 0 {
		c.MaxExporters = DefaultMaxExporters
	}
	if c.MaxTemplatesPerExporter == 0 {
		c.MaxTemplatesPerExporter = DefaultMaxTemplatesPerExporter
	}
	if c.MaxTemplatesTotal == 0 {
		c.MaxTemplatesTotal = DefaultMaxTemplatesTotal
	}
	if c.MaxFieldsPerTemplate == 0 {
		c.MaxFieldsPerTemplate = DefaultMaxFieldsPerTemplate
	}
	if c.MaxRecordBytes == 0 {
		c.MaxRecordBytes = DefaultMaxRecordBytes
	}
	if c.MaxPacketBytes == 0 {
		c.MaxPacketBytes = DefaultMaxPacketBytes
	}
	if c.PendingMaxWait == 0 {
		c.PendingMaxWait = DefaultPendingMaxWait
	}
	if c.PendingBytesPerExporter == 0 {
		c.PendingBytesPerExporter = DefaultPendingBytesPerExporter
	}
	if c.PendingBytesTotal == 0 {
		c.PendingBytesTotal = DefaultPendingBytesTotal
	}
	return c
}

func (c Config) validate() error {
	durations := []struct {
		name  string
		value time.Duration
	}{
		{name: "template ttl", value: c.TemplateTTL},
		{name: "exporter idle timeout", value: c.ExporterIdleTimeout},
		{name: "cleanup interval", value: c.CleanupInterval},
		{name: "pending max wait", value: c.PendingMaxWait},
	}
	for _, item := range durations {
		if item.value <= 0 {
			return fmt.Errorf("%w: %s must be positive", ErrConfig, item.name)
		}
	}
	limits := []struct {
		name  string
		value int
	}{
		{name: "max exporters", value: c.MaxExporters},
		{name: "max templates per exporter", value: c.MaxTemplatesPerExporter},
		{name: "max templates total", value: c.MaxTemplatesTotal},
		{name: "max fields per template", value: c.MaxFieldsPerTemplate},
		{name: "max record bytes", value: c.MaxRecordBytes},
		{name: "max packet bytes", value: c.MaxPacketBytes},
		{name: "pending bytes per exporter", value: c.PendingBytesPerExporter},
		{name: "pending bytes total", value: c.PendingBytesTotal},
	}
	for _, item := range limits {
		if item.value <= 0 {
			return fmt.Errorf("%w: %s must be positive", ErrConfig, item.name)
		}
	}
	if c.MaxPacketBytes > 65535 || c.MaxRecordBytes > 65535 {
		return fmt.Errorf("%w: packet and record byte limits must not exceed 65535", ErrConfig)
	}
	if c.MaxFieldsPerTemplate > 16382 {
		return fmt.Errorf("%w: max fields per template exceeds protocol framing", ErrConfig)
	}
	if c.MaxTemplatesPerExporter > c.MaxTemplatesTotal {
		return fmt.Errorf("%w: per-exporter template limit exceeds global limit", ErrConfig)
	}
	if c.PendingBytesPerExporter > c.PendingBytesTotal {
		return fmt.Errorf("%w: per-exporter pending byte limit exceeds global limit", ErrConfig)
	}
	return nil
}
