package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/adnope/quiver/internal/config"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

var ErrPacketRouter = errors.New("packet router")

type PacketRouter struct {
	routes map[uint16]packetRoute
}

type packetRoute struct {
	collectorID string
	collector   PacketCollector
}

func NewPacketRouter(manager *Manager, cfg config.ProxyNetFlowConfig) (*PacketRouter, error) {
	if manager == nil {
		return nil, fmt.Errorf("%w: collector manager is nil", ErrPacketRouter)
	}

	routes := cfg.Routes
	if len(routes) == 0 && strings.TrimSpace(cfg.CollectorID) != "" {
		routes = []config.ProxyNetFlowRouteConfig{{Version: 5, CollectorID: cfg.CollectorID}}
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("%w: no routes configured", ErrPacketRouter)
	}

	resolved := make(map[uint16]packetRoute, len(routes))
	for _, route := range routes {
		if route.Version != 5 && route.Version != 9 {
			return nil, fmt.Errorf("%w: unsupported version %d", ErrPacketRouter, route.Version)
		}
		if _, duplicate := resolved[route.Version]; duplicate {
			return nil, fmt.Errorf("%w: duplicate version %d", ErrPacketRouter, route.Version)
		}
		collectorID := strings.TrimSpace(route.CollectorID)
		packetCollector, ok := manager.PacketCollector(collectorID)
		if !ok {
			if manager.CollectorExists(collectorID) {
				return nil, fmt.Errorf("%w: collector %q is not packet-capable", ErrPacketRouter, collectorID)
			}
			return nil, fmt.Errorf("%w: collector %q does not exist", ErrPacketRouter, collectorID)
		}
		expectedSourceType := sourceTypeForPacketVersion(route.Version)
		if packetCollector.SourceType() != expectedSourceType {
			return nil, fmt.Errorf(
				"%w: collector %q source type %s does not match version %d",
				ErrPacketRouter,
				collectorID,
				packetCollector.SourceType(),
				route.Version,
			)
		}
		resolved[route.Version] = packetRoute{collectorID: collectorID, collector: packetCollector}
	}

	return &PacketRouter{routes: resolved}, nil
}

func (r *PacketRouter) HandlePacket(
	ctx context.Context,
	allowedCollectorIDs map[string]struct{},
	input PacketInput,
) (PacketResult, error) {
	if err := ctx.Err(); err != nil {
		return PacketResult{Status: PacketRetryable, ErrorCode: "context_done"}, fmt.Errorf("%w: %w", ErrPacketRouter, err)
	}
	if len(input.Data) < 2 {
		return PacketResult{Status: PacketRejected, ErrorCode: "malformed_packet"}, nil
	}
	if len(input.Data) > 65535 {
		return PacketResult{Status: PacketRejected, ErrorCode: "packet_too_large"}, nil
	}
	version := binary.BigEndian.Uint16(input.Data[:2])
	route, ok := r.routes[version]
	if !ok {
		return PacketResult{Status: PacketRejected, ErrorCode: "unsupported_version"}, nil
	}
	if _, allowed := allowedCollectorIDs[route.collectorID]; !allowed {
		return PacketResult{Status: PacketRejected, ErrorCode: "unauthorized_collector"}, nil
	}
	result, err := route.collector.HandlePacket(ctx, input)
	if !validPacketStatus(result.Status) {
		return PacketResult{Status: PacketRetryable, ErrorCode: "internal_error"}, fmt.Errorf(
			"%w: collector %q returned invalid packet status %q",
			ErrPacketRouter,
			route.collectorID,
			result.Status,
		)
	}
	return result, err
}

func sourceTypeForPacketVersion(version uint16) flowv1.SourceType {
	switch version {
	case 5:
		return flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5
	case 9:
		return flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9
	default:
		return flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED
	}
}

func validPacketStatus(status PacketStatus) bool {
	return status == PacketAccepted || status == PacketRetryable || status == PacketRejected
}
