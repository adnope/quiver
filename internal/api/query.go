package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	"github.com/adnope/quiver/internal/storage/postgres"
)

type FlowStore interface {
	SearchFlows(ctx context.Context, query postgres.FlowSearchQuery) (postgres.FlowSearchResult, error)
	GetFlowByID(ctx context.Context, id string) (domain.NormalizedFlowRecord, bool, error)
}

type QueryHandler struct {
	store          FlowStore
	cursorCodec    *CursorCodec
	maxQueryWindow time.Duration
	defaultLimit   int
	maxLimit       int
}

type FlowSearchResponse struct {
	Items      []FlowResponse `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
	Limit      int            `json:"limit"`
}

type FlowResponse struct {
	ID                  string         `json:"id"`
	SchemaVersion       string         `json:"schema_version"`
	IdempotencyKey      string         `json:"idempotency_key"`
	RawEventID          string         `json:"raw_event_id"`
	SourceType          string         `json:"source_type"`
	CollectorID         string         `json:"collector_id"`
	SourceHost          string         `json:"source_host"`
	SourceIP            *string        `json:"source_ip,omitempty"`
	EventStartTime      string         `json:"event_start_time"`
	EventEndTime        *string        `json:"event_end_time,omitempty"`
	DurationMS          *int64         `json:"duration_ms,omitempty"`
	SrcIP               string         `json:"src_ip"`
	DstIP               string         `json:"dst_ip"`
	SrcPort             *uint16        `json:"src_port,omitempty"`
	DstPort             *uint16        `json:"dst_port,omitempty"`
	TransportProtocol   string         `json:"transport_protocol"`
	ProtocolNumber      uint8          `json:"protocol_number"`
	Bytes               *uint64        `json:"bytes,omitempty"`
	Packets             *uint64        `json:"packets,omitempty"`
	Direction           string         `json:"direction"`
	ApplicationProtocol *string        `json:"application_protocol,omitempty"`
	NormalizationStatus string         `json:"normalization_status"`
	Attributes          map[string]any `json:"attributes,omitempty"`
}

func NewQueryHandler(cfg config.Config, store FlowStore, cursorCodec *CursorCodec) *QueryHandler {
	return &QueryHandler{
		store:          store,
		cursorCodec:    cursorCodec,
		maxQueryWindow: cfg.API.Query.MaxQueryWindow.Std(),
		defaultLimit:   cfg.API.Query.DefaultLimit,
		maxLimit:       cfg.API.Query.MaxLimit,
	}
}

// Search godoc
// @Summary Search flow records
// @Description Searches normalized flow records using required event-time bounds and optional filters.
// @Tags flows
// @Produce json
// @Security ApiKeyAuth
// @Param from query string true "Inclusive event_start_time lower bound"
// @Param to query string true "Exclusive event_start_time upper bound"
// @Param limit query int false "Page size"
// @Param cursor query string false "Signed pagination cursor"
// @Success 200 {object} FlowSearchResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /api/v1/flows [get]
func (h *QueryHandler) Search(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeDatabaseUnavailable, "database unavailable", nil)
		return
	}
	query, apiErr := h.parseFlowSearch(r)
	if apiErr != nil {
		writeError(w, r, apiErr.Status, apiErr.Code, apiErr.Message, apiErr.Details)
		return
	}
	result, err := h.store.SearchFlows(r.Context(), query)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeDatabaseUnavailable, "database unavailable", nil)
		return
	}
	response := FlowSearchResponse{
		Items: make([]FlowResponse, 0, len(result.Records)),
		Limit: query.Limit,
	}
	for _, record := range result.Records {
		response.Items = append(response.Items, flowResponse(record, query.IncludeAttributes))
	}
	if result.HasMore && len(result.Records) > 0 {
		last := result.Records[len(result.Records)-1]
		nextCursor, err := h.cursorCodec.Encode(postgres.FlowCursor{
			EventStartTime: last.EventStartTime,
			ID:             last.ID,
		})
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, CodeInternalError, "failed to encode cursor", nil)
			return
		}
		response.NextCursor = nextCursor
	}
	writeJSON(w, http.StatusOK, response)
}

// Lookup godoc
// @Summary Get flow by ID
// @Description Fetches a single normalized flow record by UUID.
// @Tags flows
// @Produce json
// @Security ApiKeyAuth
// @Param id path string true "Flow UUID"
// @Success 200 {object} FlowResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /api/v1/flows/{id} [get]
func (h *QueryHandler) Lookup(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeDatabaseUnavailable, "database unavailable", nil)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/flows/")
	if !domain.IsUUIDv7(id) {
		writeError(w, r, http.StatusBadRequest, CodeInvalidParameter, "id must be uuidv7", nil)
		return
	}
	record, found, err := h.store.GetFlowByID(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeDatabaseUnavailable, "database unavailable", nil)
		return
	}
	if !found {
		writeError(w, r, http.StatusNotFound, CodeNotFound, "flow record not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, flowResponse(record, includeAttributes(r)))
}

func (h *QueryHandler) parseFlowSearch(r *http.Request) (postgres.FlowSearchQuery, *apiHandlerError) {
	values := r.URL.Query()
	from, to, apiErr := parseRequiredRange(values.Get("from"), values.Get("to"), h.maxQueryWindow)
	if apiErr != nil {
		return postgres.FlowSearchQuery{}, apiErr
	}
	limit, apiErr := parseLimit(values.Get("limit"), h.defaultLimit, h.maxLimit)
	if apiErr != nil {
		return postgres.FlowSearchQuery{}, apiErr
	}
	query := postgres.FlowSearchQuery{
		From:                from,
		To:                  to,
		Limit:               limit,
		IncludeAttributes:   includeAttributes(r),
		CollectorID:         strings.TrimSpace(values.Get("collector_id")),
		SourceHost:          strings.TrimSpace(values.Get("source_host")),
		ApplicationProtocol: strings.TrimSpace(values.Get("application_protocol")),
	}
	if cursorValue := strings.TrimSpace(values.Get("cursor")); cursorValue != "" {
		cursor, err := h.cursorCodec.Decode(cursorValue)
		if err != nil {
			return postgres.FlowSearchQuery{}, newAPIHandlerError(http.StatusBadRequest, CodeInvalidCursor, "invalid cursor")
		}
		query.Cursor = &cursor
	}
	if apiErr := parseFlowFilters(values, &query); apiErr != nil {
		return postgres.FlowSearchQuery{}, apiErr
	}
	return query, nil
}

func parseFlowFilters(values mapValues, query *postgres.FlowSearchQuery) *apiHandlerError {
	srcIP, srcIPSet, apiErr := parseOptionalIP(values.Get("src_ip"), "src_ip")
	if apiErr != nil {
		return apiErr
	}
	dstIP, dstIPSet, apiErr := parseOptionalIP(values.Get("dst_ip"), "dst_ip")
	if apiErr != nil {
		return apiErr
	}
	srcCIDR, srcCIDRSet, apiErr := parseOptionalCIDR(values.Get("src_cidr"), "src_cidr")
	if apiErr != nil {
		return apiErr
	}
	dstCIDR, dstCIDRSet, apiErr := parseOptionalCIDR(values.Get("dst_cidr"), "dst_cidr")
	if apiErr != nil {
		return apiErr
	}
	if srcIPSet && srcCIDRSet {
		return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "src_ip and src_cidr cannot be combined")
	}
	if dstIPSet && dstCIDRSet {
		return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "dst_ip and dst_cidr cannot be combined")
	}
	if srcIPSet {
		query.SrcIP = &srcIP
	}
	if dstIPSet {
		query.DstIP = &dstIP
	}
	if srcCIDRSet {
		query.SrcCIDR = &srcCIDR
	}
	if dstCIDRSet {
		query.DstCIDR = &dstCIDR
	}
	if apiErr := parsePortFilters(values, query); apiErr != nil {
		return apiErr
	}
	protocolNumber, protocolNumberSet, apiErr := parseOptionalUint8(values.Get("protocol_number"), "protocol_number")
	if apiErr != nil {
		return apiErr
	}
	if protocolNumberSet {
		query.ProtocolNumber = &protocolNumber
	}
	if rawProtocol := strings.TrimSpace(values.Get("protocol")); rawProtocol != "" {
		protocol, ok := domain.ParseTransportProtocol(rawProtocol)
		if !ok {
			return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "protocol is invalid")
		}
		if protocolNumberSet {
			expected, _ := domain.ProtocolNumberFromName(protocol)
			if expected != protocolNumber {
				return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "protocol and protocol_number are inconsistent")
			}
		}
		query.TransportProtocol = &protocol
	}
	if sourceTypeRaw := strings.TrimSpace(values.Get("source_type")); sourceTypeRaw != "" {
		sourceType := domain.SourceType(sourceTypeRaw)
		if !domain.ValidSourceType(sourceType) {
			return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "source_type is invalid")
		}
		query.SourceType = &sourceType
	}
	if directionRaw := strings.TrimSpace(values.Get("direction")); directionRaw != "" {
		direction := domain.Direction(directionRaw)
		if !validDirection(direction) {
			return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "direction is invalid")
		}
		query.Direction = &direction
	}
	return nil
}

func parsePortFilters(values mapValues, query *postgres.FlowSearchQuery) *apiHandlerError {
	srcPort, srcPortSet, apiErr := parseOptionalUint16(values.Get("src_port"), "src_port")
	if apiErr != nil {
		return apiErr
	}
	dstPort, dstPortSet, apiErr := parseOptionalUint16(values.Get("dst_port"), "dst_port")
	if apiErr != nil {
		return apiErr
	}
	srcFrom, srcFromSet, apiErr := parseOptionalUint16(values.Get("src_port_from"), "src_port_from")
	if apiErr != nil {
		return apiErr
	}
	srcTo, srcToSet, apiErr := parseOptionalUint16(values.Get("src_port_to"), "src_port_to")
	if apiErr != nil {
		return apiErr
	}
	dstFrom, dstFromSet, apiErr := parseOptionalUint16(values.Get("dst_port_from"), "dst_port_from")
	if apiErr != nil {
		return apiErr
	}
	dstTo, dstToSet, apiErr := parseOptionalUint16(values.Get("dst_port_to"), "dst_port_to")
	if apiErr != nil {
		return apiErr
	}
	if srcPortSet && (srcFromSet || srcToSet) {
		return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "src_port cannot be combined with src_port range")
	}
	if dstPortSet && (dstFromSet || dstToSet) {
		return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "dst_port cannot be combined with dst_port range")
	}
	if srcFromSet != srcToSet {
		return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "src_port range requires both bounds")
	}
	if dstFromSet != dstToSet {
		return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "dst_port range requires both bounds")
	}
	if srcFromSet && srcFrom > srcTo {
		return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "src_port range is invalid")
	}
	if dstFromSet && dstFrom > dstTo {
		return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "dst_port range is invalid")
	}
	if srcPortSet {
		query.SrcPort = &srcPort
	}
	if dstPortSet {
		query.DstPort = &dstPort
	}
	if srcFromSet {
		query.SrcPortRange = &postgres.PortRange{From: srcFrom, To: srcTo}
	}
	if dstFromSet {
		query.DstPortRange = &postgres.PortRange{From: dstFrom, To: dstTo}
	}
	return nil
}

func flowResponse(record domain.NormalizedFlowRecord, includeAttrs bool) FlowResponse {
	response := FlowResponse{
		ID:                  record.ID,
		SchemaVersion:       record.SchemaVersion,
		IdempotencyKey:      record.IdempotencyKey,
		RawEventID:          record.RawEventID,
		SourceType:          string(record.SourceType),
		CollectorID:         record.CollectorID,
		SourceHost:          record.SourceHost,
		EventStartTime:      record.EventStartTime.UTC().Format(time.RFC3339Nano),
		DurationMS:          record.DurationMS,
		SrcIP:               record.SrcIP.String(),
		DstIP:               record.DstIP.String(),
		SrcPort:             record.SrcPort,
		DstPort:             record.DstPort,
		TransportProtocol:   string(record.TransportProtocol),
		ProtocolNumber:      record.ProtocolNumber,
		Bytes:               record.Bytes,
		Packets:             record.Packets,
		Direction:           string(record.Direction),
		ApplicationProtocol: record.ApplicationProtocol,
		NormalizationStatus: string(record.NormalizationStatus),
	}
	if record.SourceIP != nil {
		value := record.SourceIP.String()
		response.SourceIP = &value
	}
	if record.EventEndTime != nil {
		value := record.EventEndTime.UTC().Format(time.RFC3339Nano)
		response.EventEndTime = &value
	}
	if includeAttrs {
		response.Attributes = rawAttributesToAny(record.Attributes)
	}
	return response
}

func includeAttributes(r *http.Request) bool {
	for _, item := range strings.Split(r.URL.Query().Get("include"), ",") {
		if strings.TrimSpace(item) == "attributes" {
			return true
		}
	}
	return false
}

type mapValues interface {
	Get(string) string
}

type apiHandlerError struct {
	Status  int
	Code    string
	Message string
	Details map[string]any
}

func newAPIHandlerError(status int, code string, message string) *apiHandlerError {
	return &apiHandlerError{Status: status, Code: code, Message: message}
}

func parseRequiredRange(fromRaw string, toRaw string, maxWindow time.Duration) (time.Time, time.Time, *apiHandlerError) {
	if strings.TrimSpace(fromRaw) == "" {
		return time.Time{}, time.Time{}, newAPIHandlerError(http.StatusBadRequest, CodeMissingRequiredParameter, "from is required")
	}
	if strings.TrimSpace(toRaw) == "" {
		return time.Time{}, time.Time{}, newAPIHandlerError(http.StatusBadRequest, CodeMissingRequiredParameter, "to is required")
	}
	from, err := time.Parse(time.RFC3339Nano, fromRaw)
	if err != nil {
		return time.Time{}, time.Time{}, newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "from must be RFC3339")
	}
	to, err := time.Parse(time.RFC3339Nano, toRaw)
	if err != nil {
		return time.Time{}, time.Time{}, newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "to must be RFC3339")
	}
	if !from.Before(to) {
		return time.Time{}, time.Time{}, newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "from must be before to")
	}
	if to.Sub(from) > maxWindow {
		return time.Time{}, time.Time{}, newAPIHandlerError(http.StatusBadRequest, CodeQueryWindowTooLarge, "query window is too large")
	}
	return from.UTC(), to.UTC(), nil
}

func parseLimit(raw string, defaultLimit int, maxLimit int) (int, *apiHandlerError) {
	if strings.TrimSpace(raw) == "" {
		return defaultLimit, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "limit must be a positive integer")
	}
	if value > maxLimit {
		return 0, newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "limit exceeds maximum")
	}
	return value, nil
}

func parseOptionalIP(raw string, field string) (netip.Addr, bool, *apiHandlerError) {
	if strings.TrimSpace(raw) == "" {
		return netip.Addr{}, false, nil
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, false, newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, field+" is invalid")
	}
	return ip, true, nil
}

func parseOptionalCIDR(raw string, field string) (netip.Prefix, bool, *apiHandlerError) {
	if strings.TrimSpace(raw) == "" {
		return netip.Prefix{}, false, nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, false, newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, field+" is invalid")
	}
	return prefix.Masked(), true, nil
}

func parseOptionalUint16(raw string, field string) (uint16, bool, *apiHandlerError) {
	if strings.TrimSpace(raw) == "" {
		return 0, false, nil
	}
	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return 0, false, newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, field+" is invalid")
	}
	return uint16(value), true, nil
}

func parseOptionalUint8(raw string, field string) (uint8, bool, *apiHandlerError) {
	if strings.TrimSpace(raw) == "" {
		return 0, false, nil
	}
	value, err := strconv.ParseUint(raw, 10, 8)
	if err != nil {
		return 0, false, newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, field+" is invalid")
	}
	return uint8(value), true, nil
}

func validDirection(direction domain.Direction) bool {
	switch direction {
	case domain.DirectionInbound, domain.DirectionOutbound, domain.DirectionInternal, domain.DirectionExternal, domain.DirectionUnknown:
		return true
	default:
		return false
	}
}

func rawAttributesToAny(attrs map[string]json.RawMessage) map[string]any {
	if attrs == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(attrs))
	for key, value := range attrs {
		var decoded any
		if err := json.Unmarshal(value, &decoded); err == nil {
			out[key] = decoded
		}
	}
	return out
}
