package collector

import (
	"errors"
	"fmt"
	"strings"
)

var ErrRegistry = errors.New("collector registry")

type Registry struct {
	plugins map[string]Plugin
}

func NewRegistry() *Registry {
	return &Registry{plugins: map[string]Plugin{}}
}

func (r *Registry) Register(plugin Plugin) error {
	if plugin == nil {
		return fmt.Errorf("%w: plugin is nil", ErrRegistry)
	}
	pluginType := strings.TrimSpace(plugin.Type())
	if pluginType == "" {
		return fmt.Errorf("%w: plugin type is required", ErrRegistry)
	}
	if r.plugins == nil {
		r.plugins = map[string]Plugin{}
	}
	if _, exists := r.plugins[pluginType]; exists {
		return fmt.Errorf("%w: duplicate plugin type %q", ErrRegistry, pluginType)
	}
	r.plugins[pluginType] = plugin
	return nil
}

func (r *Registry) Lookup(pluginType string) (Plugin, bool) {
	if r == nil {
		return nil, false
	}
	plugin, ok := r.plugins[strings.TrimSpace(pluginType)]
	return plugin, ok
}

func (r *Registry) MustLookup(pluginType string) (Plugin, error) {
	plugin, ok := r.Lookup(pluginType)
	if !ok {
		return nil, fmt.Errorf("%w: unknown collector type %q", ErrRegistry, strings.TrimSpace(pluginType))
	}
	return plugin, nil
}
