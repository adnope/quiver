package builtin

import (
	"github.com/adnope/quiver/internal/collector"
	"github.com/adnope/quiver/internal/collector/netflow"
)

func NewRegistry() (*collector.Registry, error) {
	registry := collector.NewRegistry()
	if err := registry.Register(netflow.NewPlugin()); err != nil {
		return nil, err
	}
	return registry, nil
}
