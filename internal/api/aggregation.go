package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	"github.com/adnope/quiver/internal/storage/postgres"
)

const (
	aggregationOrderProtocols  = "value_desc_flow_count_desc_protocol_number_asc_transport_protocol_asc"
	aggregationOrderTopPorts   = "value_desc_flow_count_desc_port_asc"
	aggregationOrderTopTalkers = "value_desc_flow_count_desc_ip_asc"
)

type AggregationStore interface {
	TopTalkers(ctx context.Context, query postgres.AggregationQuery) ([]postgres.TopTalkerRow, error)
	TopPorts(ctx context.Context, query postgres.AggregationQuery) ([]postgres.TopPortRow, error)
	ProtocolDistribution(ctx context.Context, query postgres.AggregationQuery) ([]postgres.ProtocolRow, error)
}

type AggregationHandler struct {
	store          AggregationStore
	cursorCodec    *CursorCodec
	maxQueryWindow time.Duration
	defaultLimit   int
	maxLimit       int
}

type TopTalkersResponse struct {
	Items      []TopTalkerResponse `json:"items"`
	From       string              `json:"from"`
	To         string              `json:"to"`
	Limit      int                 `json:"limit"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type TopTalkerResponse struct {
	IP        string `json:"ip"`
	Metric    string `json:"metric"`
	Value     uint64 `json:"value"`
	FlowCount uint64 `json:"flow_count"`
}

type TopPortsResponse struct {
	Items      []TopPortResponse `json:"items"`
	From       string            `json:"from"`
	To         string            `json:"to"`
	Limit      int               `json:"limit"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

type TopPortResponse struct {
	Port      uint16 `json:"port"`
	Metric    string `json:"metric"`
	Value     uint64 `json:"value"`
	FlowCount uint64 `json:"flow_count"`
}

type ProtocolsResponse struct {
	Items      []ProtocolResponse `json:"items"`
	From       string             `json:"from"`
	To         string             `json:"to"`
	Limit      int                `json:"limit"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type ProtocolResponse struct {
	ProtocolNumber    uint8  `json:"protocol_number"`
	TransportProtocol string `json:"transport_protocol"`
	Metric            string `json:"metric"`
	Value             uint64 `json:"value"`
	FlowCount         uint64 `json:"flow_count"`
}

func NewAggregationHandler(cfg config.Config, store AggregationStore, cursorCodec *CursorCodec) *AggregationHandler {
	return &AggregationHandler{
		store:          store,
		cursorCodec:    cursorCodec,
		maxQueryWindow: cfg.API.Query.MaxQueryWindow.Std(),
		defaultLimit:   cfg.API.Query.AggregationDefaultLimit,
		maxLimit:       cfg.API.Query.MaxLimit,
	}
}

// TopTalkers godoc
// @Summary Top talkers
// @Description Aggregates flows by source or destination IP.
// @Tags aggregations
// @Produce json
// @Security ApiKeyAuth
// @Param from query string true "Inclusive event_start_time lower bound"
// @Param to query string true "Exclusive event_start_time upper bound"
// @Param direction query string true "src or dst"
// @Param metric query string false "Aggregation metric" Enums(bytes,packets,flows)
// @Param limit query int false "Maximum number of rows"
// @Param cursor query string false "Signed pagination cursor"
// @Param source_type query string false "Source type filter" Enums(netflow_v5,netflow_v9,zeek_conn_json,suricata_eve_json,rest_json,syslog_cef,syslog_leef)
// @Param src_ip query string false "Exact source IP filter"
// @Param dst_ip query string false "Exact destination IP filter"
// @Param protocol_number query int false "IP protocol number filter"
// @Success 200 {object} TopTalkersResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /api/v1/aggregations/top-talkers [get]
func (h *AggregationHandler) TopTalkers(w http.ResponseWriter, r *http.Request) {
	query, apiErr := h.parseAggregationQuery(r, true, postgres.AggregationEndpointTopTalkers)
	if apiErr != nil {
		writeError(w, r, apiErr.Status, apiErr.Code, apiErr.Message, apiErr.Details)
		return
	}
	requestedLimit := query.Limit
	storeQuery := query
	storeQuery.Limit = requestedLimit + 1
	rows, err := h.store.TopTalkers(r.Context(), storeQuery)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeDatabaseUnavailable, "database unavailable", nil)
		return
	}
	hasMore := len(rows) > requestedLimit
	if hasMore {
		rows = rows[:requestedLimit]
	}
	items := make([]TopTalkerResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, TopTalkerResponse{
			IP:        row.IP.String(),
			Metric:    string(row.Metric),
			Value:     row.Value,
			FlowCount: row.FlowCount,
		})
	}
	response := TopTalkersResponse{
		Items: items,
		From:  query.From.Format(time.RFC3339Nano),
		To:    query.To.Format(time.RFC3339Nano),
		Limit: requestedLimit,
	}
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		nextCursor, err := h.encodeAggregationCursor(query, postgres.AggregationCursor{
			Endpoint:  postgres.AggregationEndpointTopTalkers,
			Metric:    query.Metric,
			Direction: query.Direction,
			Value:     last.Value,
			FlowCount: last.FlowCount,
			IP:        &last.IP,
		})
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, CodeInternalError, "failed to encode cursor", nil)
			return
		}
		response.NextCursor = nextCursor
	}
	writeJSON(w, http.StatusOK, response)
}

// TopPorts godoc
// @Summary Top ports
// @Description Aggregates flows by source or destination port.
// @Tags aggregations
// @Produce json
// @Security ApiKeyAuth
// @Param from query string true "Inclusive event_start_time lower bound"
// @Param to query string true "Exclusive event_start_time upper bound"
// @Param direction query string true "src or dst"
// @Param metric query string false "Aggregation metric" Enums(bytes,packets,flows)
// @Param limit query int false "Maximum number of rows"
// @Param cursor query string false "Signed pagination cursor"
// @Param source_type query string false "Source type filter" Enums(netflow_v5,netflow_v9,zeek_conn_json,suricata_eve_json,rest_json,syslog_cef,syslog_leef)
// @Param src_ip query string false "Exact source IP filter"
// @Param dst_ip query string false "Exact destination IP filter"
// @Param protocol_number query int false "IP protocol number filter"
// @Success 200 {object} TopPortsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /api/v1/aggregations/top-ports [get]
func (h *AggregationHandler) TopPorts(w http.ResponseWriter, r *http.Request) {
	query, apiErr := h.parseAggregationQuery(r, true, postgres.AggregationEndpointTopPorts)
	if apiErr != nil {
		writeError(w, r, apiErr.Status, apiErr.Code, apiErr.Message, apiErr.Details)
		return
	}
	requestedLimit := query.Limit
	storeQuery := query
	storeQuery.Limit = requestedLimit + 1
	rows, err := h.store.TopPorts(r.Context(), storeQuery)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeDatabaseUnavailable, "database unavailable", nil)
		return
	}
	hasMore := len(rows) > requestedLimit
	if hasMore {
		rows = rows[:requestedLimit]
	}
	items := make([]TopPortResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, TopPortResponse{
			Port:      row.Port,
			Metric:    string(row.Metric),
			Value:     row.Value,
			FlowCount: row.FlowCount,
		})
	}
	response := TopPortsResponse{
		Items: items,
		From:  query.From.Format(time.RFC3339Nano),
		To:    query.To.Format(time.RFC3339Nano),
		Limit: requestedLimit,
	}
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		nextCursor, err := h.encodeAggregationCursor(query, postgres.AggregationCursor{
			Endpoint:  postgres.AggregationEndpointTopPorts,
			Metric:    query.Metric,
			Direction: query.Direction,
			Value:     last.Value,
			FlowCount: last.FlowCount,
			Port:      &last.Port,
		})
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, CodeInternalError, "failed to encode cursor", nil)
			return
		}
		response.NextCursor = nextCursor
	}
	writeJSON(w, http.StatusOK, response)
}

// Protocols godoc
// @Summary Protocol distribution
// @Description Aggregates flows by protocol number and transport protocol.
// @Tags aggregations
// @Produce json
// @Security ApiKeyAuth
// @Param from query string true "Inclusive event_start_time lower bound"
// @Param to query string true "Exclusive event_start_time upper bound"
// @Param metric query string false "Aggregation metric" Enums(bytes,packets,flows)
// @Param limit query int false "Maximum number of rows"
// @Param cursor query string false "Signed pagination cursor"
// @Param source_type query string false "Source type filter" Enums(netflow_v5,netflow_v9,zeek_conn_json,suricata_eve_json,rest_json,syslog_cef,syslog_leef)
// @Param src_ip query string false "Exact source IP filter"
// @Param dst_ip query string false "Exact destination IP filter"
// @Param protocol_number query int false "IP protocol number filter"
// @Success 200 {object} ProtocolsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /api/v1/aggregations/protocols [get]
func (h *AggregationHandler) Protocols(w http.ResponseWriter, r *http.Request) {
	query, apiErr := h.parseAggregationQuery(r, false, postgres.AggregationEndpointProtocols)
	if apiErr != nil {
		writeError(w, r, apiErr.Status, apiErr.Code, apiErr.Message, apiErr.Details)
		return
	}
	requestedLimit := query.Limit
	storeQuery := query
	storeQuery.Limit = requestedLimit + 1
	rows, err := h.store.ProtocolDistribution(r.Context(), storeQuery)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeDatabaseUnavailable, "database unavailable", nil)
		return
	}
	hasMore := len(rows) > requestedLimit
	if hasMore {
		rows = rows[:requestedLimit]
	}
	items := make([]ProtocolResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, ProtocolResponse{
			ProtocolNumber:    row.ProtocolNumber,
			TransportProtocol: string(row.TransportProtocol),
			Metric:            string(row.Metric),
			Value:             row.Value,
			FlowCount:         row.FlowCount,
		})
	}
	response := ProtocolsResponse{
		Items: items,
		From:  query.From.Format(time.RFC3339Nano),
		To:    query.To.Format(time.RFC3339Nano),
		Limit: requestedLimit,
	}
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		nextCursor, err := h.encodeAggregationCursor(query, postgres.AggregationCursor{
			Endpoint:          postgres.AggregationEndpointProtocols,
			Metric:            query.Metric,
			Value:             last.Value,
			FlowCount:         last.FlowCount,
			ProtocolNumber:    &last.ProtocolNumber,
			TransportProtocol: &last.TransportProtocol,
		})
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, CodeInternalError, "failed to encode cursor", nil)
			return
		}
		response.NextCursor = nextCursor
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *AggregationHandler) parseAggregationQuery(r *http.Request, requireDirection bool, endpoint postgres.AggregationEndpoint) (postgres.AggregationQuery, *apiHandlerError) {
	if h == nil || h.store == nil {
		return postgres.AggregationQuery{}, newAPIHandlerError(http.StatusServiceUnavailable, CodeDatabaseUnavailable, "database unavailable")
	}
	values := r.URL.Query()
	from, to, apiErr := parseRequiredRange(values.Get("from"), values.Get("to"), h.maxQueryWindow)
	if apiErr != nil {
		return postgres.AggregationQuery{}, apiErr
	}
	limit, apiErr := parseLimit(values.Get("limit"), h.defaultLimit, h.maxLimit)
	if apiErr != nil {
		return postgres.AggregationQuery{}, apiErr
	}
	metric := postgres.AggregationMetric(strings.TrimSpace(values.Get("metric")))
	if metric == "" {
		metric = postgres.AggregationMetricBytes
	}
	switch metric {
	case postgres.AggregationMetricBytes, postgres.AggregationMetricPackets, postgres.AggregationMetricFlows:
	default:
		return postgres.AggregationQuery{}, newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "metric is invalid")
	}
	query := postgres.AggregationQuery{From: from, To: to, Metric: metric, Limit: limit}
	if requireDirection {
		direction := postgres.AggregationDirection(strings.TrimSpace(values.Get("direction")))
		if direction != postgres.AggregationDirectionSrc && direction != postgres.AggregationDirectionDst {
			return postgres.AggregationQuery{}, newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "direction must be src or dst")
		}
		query.Direction = direction
	}
	if apiErr := parseAggregationFilters(values, &query); apiErr != nil {
		return postgres.AggregationQuery{}, apiErr
	}
	if cursorValue := strings.TrimSpace(values.Get("cursor")); cursorValue != "" {
		if h.cursorCodec == nil {
			return postgres.AggregationQuery{}, newAPIHandlerError(http.StatusBadRequest, CodeInvalidCursor, "invalid cursor")
		}
		cursor, err := h.cursorCodec.DecodeAggregation(cursorValue)
		if err != nil || !aggregationCursorMatchesQuery(cursor, endpoint, query) {
			return postgres.AggregationQuery{}, newAPIHandlerError(http.StatusBadRequest, CodeInvalidCursor, "invalid cursor")
		}
		query.Cursor = &cursor
	}
	return query, nil
}

func parseAggregationFilters(values mapValues, query *postgres.AggregationQuery) *apiHandlerError {
	srcIP, srcIPSet, apiErr := parseOptionalIP(values.Get("src_ip"), "src_ip")
	if apiErr != nil {
		return apiErr
	}
	dstIP, dstIPSet, apiErr := parseOptionalIP(values.Get("dst_ip"), "dst_ip")
	if apiErr != nil {
		return apiErr
	}
	protocolNumber, protocolNumberSet, apiErr := parseOptionalUint8(values.Get("protocol_number"), "protocol_number")
	if apiErr != nil {
		return apiErr
	}
	if srcIPSet {
		query.SrcIP = &srcIP
	}
	if dstIPSet {
		query.DstIP = &dstIP
	}
	if protocolNumberSet {
		query.ProtocolNumber = &protocolNumber
	}
	if sourceTypeRaw := strings.TrimSpace(values.Get("source_type")); sourceTypeRaw != "" {
		sourceType := domain.SourceType(sourceTypeRaw)
		if !domain.ValidSourceType(sourceType) {
			return newAPIHandlerError(http.StatusBadRequest, CodeInvalidParameter, "source_type is invalid")
		}
		query.SourceType = &sourceType
	}
	return nil
}

func (h *AggregationHandler) encodeAggregationCursor(query postgres.AggregationQuery, cursor postgres.AggregationCursor) (string, error) {
	cursor.QueryHash = aggregationQueryHash(cursor.Endpoint, query)
	return h.cursorCodec.EncodeAggregation(cursor)
}

func aggregationCursorMatchesQuery(cursor postgres.AggregationCursor, endpoint postgres.AggregationEndpoint, query postgres.AggregationQuery) bool {
	if cursor.Endpoint != endpoint || cursor.QueryHash != aggregationQueryHash(endpoint, query) || cursor.Metric != query.Metric {
		return false
	}
	if endpoint != postgres.AggregationEndpointProtocols && cursor.Direction != query.Direction {
		return false
	}
	return true
}

type aggregationQueryFingerprint struct {
	Endpoint       string `json:"endpoint"`
	From           string `json:"from"`
	To             string `json:"to"`
	Metric         string `json:"metric"`
	Direction      string `json:"direction,omitempty"`
	SrcIP          string `json:"src_ip,omitempty"`
	DstIP          string `json:"dst_ip,omitempty"`
	ProtocolNumber string `json:"protocol_number,omitempty"`
	SourceType     string `json:"source_type,omitempty"`
	Order          string `json:"order"`
}

func aggregationQueryHash(endpoint postgres.AggregationEndpoint, query postgres.AggregationQuery) string {
	fingerprint := aggregationQueryFingerprint{
		Endpoint:  string(endpoint),
		From:      query.From.UTC().Format(time.RFC3339Nano),
		To:        query.To.UTC().Format(time.RFC3339Nano),
		Metric:    string(query.Metric),
		Direction: string(query.Direction),
		Order:     aggregationOrder(endpoint),
	}
	if query.SrcIP != nil {
		fingerprint.SrcIP = query.SrcIP.String()
	}
	if query.DstIP != nil {
		fingerprint.DstIP = query.DstIP.String()
	}
	if query.ProtocolNumber != nil {
		fingerprint.ProtocolNumber = strconv.Itoa(int(*query.ProtocolNumber))
	}
	if query.SourceType != nil {
		fingerprint.SourceType = string(*query.SourceType)
	}
	data, err := json.Marshal(fingerprint)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func aggregationOrder(endpoint postgres.AggregationEndpoint) string {
	switch endpoint {
	case postgres.AggregationEndpointTopTalkers:
		return aggregationOrderTopTalkers
	case postgres.AggregationEndpointTopPorts:
		return aggregationOrderTopPorts
	default:
		return aggregationOrderProtocols
	}
}
