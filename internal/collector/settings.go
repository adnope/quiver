package collector

import (
	"bytes"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

type SettingsMode string

const (
	NoSettings       SettingsMode = "none"
	SettingsOptional SettingsMode = "optional"
	SettingsRequired SettingsMode = "required"
)

var ErrSettings = errors.New("collector settings")

type InstanceConfig struct {
	Type        string
	CollectorID string
	Settings    *yaml.Node
}

func ValidateSettingsMode(mode SettingsMode, settings *yaml.Node) error {
	switch mode {
	case NoSettings:
		if settings != nil {
			return fmt.Errorf("%w: settings must be omitted", ErrSettings)
		}
	case SettingsOptional:
		return nil
	case SettingsRequired:
		if settings == nil {
			return fmt.Errorf("%w: settings are required", ErrSettings)
		}
	default:
		return fmt.Errorf("%w: unsupported settings mode %q", ErrSettings, mode)
	}
	return nil
}

func DecodeSettingsStrict(mode SettingsMode, settings *yaml.Node, out any) error {
	if err := ValidateSettingsMode(mode, settings); err != nil {
		return err
	}
	if settings == nil {
		return nil
	}
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	if err := encoder.Encode(settings); err != nil {
		_ = encoder.Close()
		return fmt.Errorf("%w: encode settings: %w", ErrSettings, err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("%w: encode settings: %w", ErrSettings, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(buf.Bytes()))
	decoder.KnownFields(true)
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("%w: decode settings: %w", ErrSettings, err)
	}
	return nil
}
