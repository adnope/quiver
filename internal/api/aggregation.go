package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	"github.com/adnope/quiver/internal/storage/postgres"
)

type AggregationStore interface {
	TopTalkers(ctx context.Context, query postgres.AggregationQuery) ([]postgres.TopTalkerRow, error)
	TopPorts(ctx context.Context, query postgres.AggregationQuery) ([]postgres.TopPortRow, error)
	ProtocolDistribution(ctx context.Context, query postgres.AggregationQuery) ([]postgres.ProtocolRow, error)
}

type AggregationHandler struct {
	store          AggregationStore
	maxQueryWindow time.Duration
	defaultLimit   int
	maxLimit       int
}

type TopTalkersResponse struct {
	Items []TopTalkerResponse `json:"items"`
	From  string              `json:"from"`
	To    string              `json:"to"`
	Limit int                 `json:"limit"`
}

type TopTalkerResponse struct {
	IP        string `json:"ip"`
	Metric    string `json:"metric"`
	Value     uint64 `json:"value"`
	FlowCount uint64 `json:"flow_count"`
}

type TopPortsResponse struct {
	Items []TopPortResponse `json:"items"`
	From  string            `json:"from"`
	To    string            `json:"to"`
	Limit int               `json:"limit"`
}

type TopPortResponse struct {
	Port      uint16 `json:"port"`
	Metric    string `json:"metric"`
	Value     uint64 `json:"value"`
	FlowCount uint64 `json:"flow_count"`
}

type ProtocolsResponse struct {
	Items []ProtocolResponse `json:"items"`
	From  string             `json:"from"`
	To    string             `json:"to"`
	Limit int                `json:"limit"`
}

type ProtocolResponse struct {
	ProtocolNumber    uint8  `json:"protocol_number"`
	TransportProtocol string `json:"transport_protocol"`
	Metric            string `json:"metric"`
	Value             uint64 `json:"value"`
	FlowCount         uint64 `json:"flow_count"`
}

func NewAggregationHandler(cfg config.Config, store AggregationStore) *AggregationHandler {
	return &AggregationHandler{
		store:          store,
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
	query, apiErr := h.parseAggregationQuery(r, true)
	if apiErr != nil {
		writeError(w, r, apiErr.Status, apiErr.Code, apiErr.Message, apiErr.Details)
		return
	}
	rows, err := h.store.TopTalkers(r.Context(), query)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeDatabaseUnavailable, "database unavailable", nil)
		return
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
	writeJSON(w, http.StatusOK, TopTalkersResponse{
		Items: items,
		From:  query.From.Format(time.RFC3339Nano),
		To:    query.To.Format(time.RFC3339Nano),
		Limit: query.Limit,
	})
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
	query, apiErr := h.parseAggregationQuery(r, true)
	if apiErr != nil {
		writeError(w, r, apiErr.Status, apiErr.Code, apiErr.Message, apiErr.Details)
		return
	}
	rows, err := h.store.TopPorts(r.Context(), query)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeDatabaseUnavailable, "database unavailable", nil)
		return
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
	writeJSON(w, http.StatusOK, TopPortsResponse{
		Items: items,
		From:  query.From.Format(time.RFC3339Nano),
		To:    query.To.Format(time.RFC3339Nano),
		Limit: query.Limit,
	})
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
	query, apiErr := h.parseAggregationQuery(r, false)
	if apiErr != nil {
		writeError(w, r, apiErr.Status, apiErr.Code, apiErr.Message, apiErr.Details)
		return
	}
	rows, err := h.store.ProtocolDistribution(r.Context(), query)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeDatabaseUnavailable, "database unavailable", nil)
		return
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
	writeJSON(w, http.StatusOK, ProtocolsResponse{
		Items: items,
		From:  query.From.Format(time.RFC3339Nano),
		To:    query.To.Format(time.RFC3339Nano),
		Limit: query.Limit,
	})
}

func (h *AggregationHandler) parseAggregationQuery(r *http.Request, requireDirection bool) (postgres.AggregationQuery, *apiHandlerError) {
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
