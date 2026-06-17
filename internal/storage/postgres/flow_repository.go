package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/adnope/quiver/internal/domain"
)

var (
	ErrInvalidFlowQuery = errors.New("postgres: invalid flow query")
	ErrFlowNotFound     = errors.New("postgres: flow record not found")
)

type FlowCursor struct {
	EventStartTime time.Time
	ID             string
}

type PortRange struct {
	From uint16
	To   uint16
}

type FlowSearchQuery struct {
	From                time.Time
	To                  time.Time
	Cursor              *FlowCursor
	Limit               int
	IncludeAttributes   bool
	SrcIP               *netip.Addr
	DstIP               *netip.Addr
	SrcCIDR             *netip.Prefix
	DstCIDR             *netip.Prefix
	SrcPort             *uint16
	DstPort             *uint16
	SrcPortRange        *PortRange
	DstPortRange        *PortRange
	ProtocolNumber      *uint8
	TransportProtocol   *domain.TransportProtocol
	SourceType          *domain.SourceType
	CollectorID         string
	SourceHost          string
	ApplicationProtocol string
	Direction           *domain.Direction
}

type FlowSearchResult struct {
	Records []domain.NormalizedFlowRecord
	HasMore bool
}

type AggregationMetric string

const (
	AggregationMetricBytes   AggregationMetric = "bytes"
	AggregationMetricPackets AggregationMetric = "packets"
	AggregationMetricFlows   AggregationMetric = "flows"
)

type AggregationDirection string

const (
	AggregationDirectionSrc AggregationDirection = "src"
	AggregationDirectionDst AggregationDirection = "dst"
)

type AggregationQuery struct {
	From           time.Time
	To             time.Time
	Metric         AggregationMetric
	Limit          int
	Direction      AggregationDirection
	SrcIP          *netip.Addr
	DstIP          *netip.Addr
	ProtocolNumber *uint8
	SourceType     *domain.SourceType
}

type TopTalkerRow struct {
	IP        netip.Addr
	Metric    AggregationMetric
	Value     uint64
	FlowCount uint64
}

type TopPortRow struct {
	Port      uint16
	Metric    AggregationMetric
	Value     uint64
	FlowCount uint64
}

type ProtocolRow struct {
	ProtocolNumber    uint8
	TransportProtocol domain.TransportProtocol
	Metric            AggregationMetric
	Value             uint64
	FlowCount         uint64
}

type InsertResult struct {
	Attempted    int
	Inserted     int
	Deduplicated int
}

type FlowRepository struct {
	db *sql.DB
}

func NewFlowRepository(db *sql.DB) (*FlowRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: db is nil", ErrInvalidDatabaseConfig)
	}
	return &FlowRepository{db: db}, nil
}

func (r *FlowRepository) InsertFlowRecords(ctx context.Context, records []domain.NormalizedFlowRecord) (InsertResult, error) {
	if ctx == nil {
		return InsertResult{}, fmt.Errorf("%w: context is nil", ErrInvalidFlowQuery)
	}
	if err := ctx.Err(); err != nil {
		return InsertResult{}, fmt.Errorf("insert flow records: %w", err)
	}
	if r == nil || r.db == nil {
		return InsertResult{}, fmt.Errorf("%w: db is nil", ErrInvalidDatabaseConfig)
	}
	if len(records) == 0 {
		return InsertResult{}, nil
	}
	for i, record := range records {
		if err := domain.ValidateNormalizedFlowRecord(record); err != nil {
			return InsertResult{}, fmt.Errorf("%w: record %d: %v", ErrInvalidFlowQuery, i, err)
		}
	}

	var builder strings.Builder
	args := make([]any, 0, len(records)*33)
	builder.WriteString(`INSERT INTO quiver.flow_records (
id, schema_version, idempotency_key, raw_event_id,
source_type, collector_id, source_host, source_ip, ingested_at, normalized_at,
event_start_time, event_end_time, duration_ms,
src_ip, dst_ip, src_port, dst_port, ip_version, transport_protocol, protocol_number,
bytes, packets, tcp_flags, flow_state,
direction, input_interface, output_interface, next_hop_ip,
application_protocol, sampling_rate, normalization_status, normalization_error, attributes
) VALUES `)
	for i, record := range records {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString("(")
		for col := 0; col < 33; col++ {
			if col > 0 {
				builder.WriteString(", ")
			}
			fmt.Fprintf(&builder, "$%d", len(args)+col+1)
		}
		builder.WriteString(")")
		args = append(args, insertArgs(record)...)
	}
	builder.WriteString(" ON CONFLICT (event_start_time, idempotency_key) DO NOTHING")

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return InsertResult{}, fmt.Errorf("begin flow insert transaction: %w", err)
	}
	result, execErr := tx.ExecContext(ctx, builder.String(), args...)
	if execErr != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return InsertResult{}, errors.Join(
				fmt.Errorf("insert flow records: %w", execErr),
				fmt.Errorf("rollback flow insert transaction: %w", rollbackErr),
			)
		}
		return InsertResult{}, fmt.Errorf("insert flow records: %w", execErr)
	}
	if err := tx.Commit(); err != nil {
		return InsertResult{}, fmt.Errorf("commit flow insert transaction: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return InsertResult{}, fmt.Errorf("read inserted flow row count: %w", err)
	}
	return InsertResult{
		Attempted:    len(records),
		Inserted:     int(inserted),
		Deduplicated: len(records) - int(inserted),
	}, nil
}

func (r *FlowRepository) SearchFlows(ctx context.Context, query FlowSearchQuery) (FlowSearchResult, error) {
	if err := validateSearchQuery(query); err != nil {
		return FlowSearchResult{}, err
	}
	where, args := buildFlowWhere(query)
	limit := query.Limit + 1
	args = append(args, limit)
	// security: SQL fragments are fixed allow-listed clauses; all request values remain parameterized.
	// #nosec G202
	sqlQuery := `SELECT ` + flowRecordColumns() + `
FROM quiver.flow_records
WHERE ` + where + `
ORDER BY event_start_time DESC, id DESC
LIMIT $` + fmt.Sprint(len(args))

	rows, err := r.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return FlowSearchResult{}, fmt.Errorf("query flow records: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	records := make([]domain.NormalizedFlowRecord, 0, query.Limit)
	for rows.Next() {
		record, err := scanFlowRecord(rows)
		if err != nil {
			return FlowSearchResult{}, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return FlowSearchResult{}, fmt.Errorf("iterate flow records: %w", err)
	}

	hasMore := len(records) > query.Limit
	if hasMore {
		records = records[:query.Limit]
	}
	if !query.IncludeAttributes {
		for i := range records {
			records[i].Attributes = nil
		}
	}
	return FlowSearchResult{Records: records, HasMore: hasMore}, nil
}

func (r *FlowRepository) GetFlowByID(ctx context.Context, id string) (domain.NormalizedFlowRecord, bool, error) {
	if !domain.IsUUIDv7(id) {
		return domain.NormalizedFlowRecord{}, false, fmt.Errorf("%w: id must be uuidv7", ErrInvalidFlowQuery)
	}
	// security: selected columns are a fixed internal list; id remains parameterized.
	// #nosec G202
	row := r.db.QueryRowContext(
		ctx,
		`SELECT `+flowRecordColumns()+`
FROM quiver.flow_records
WHERE id = $1
LIMIT 1`,
		id,
	)
	record, err := scanFlowRecord(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.NormalizedFlowRecord{}, false, nil
		}
		return domain.NormalizedFlowRecord{}, false, err
	}
	return record, true, nil
}

func (r *FlowRepository) TopTalkers(ctx context.Context, query AggregationQuery) ([]TopTalkerRow, error) {
	if err := validateAggregationQuery(query, true); err != nil {
		return nil, err
	}
	groupColumn := "src_ip"
	if query.Direction == AggregationDirectionDst {
		groupColumn = "dst_ip"
	}
	sqlQuery, args := buildAggregationSQL(query, groupColumn, "true")
	rows, err := r.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query top talkers: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	items := []TopTalkerRow{}
	for rows.Next() {
		var ipText string
		var value uint64
		var flowCount uint64
		if err := rows.Scan(&ipText, &value, &flowCount); err != nil {
			return nil, fmt.Errorf("scan top talker: %w", err)
		}
		ip, err := netip.ParseAddr(ipText)
		if err != nil {
			return nil, fmt.Errorf("parse top talker ip: %w", err)
		}
		items = append(items, TopTalkerRow{IP: ip, Metric: query.Metric, Value: value, FlowCount: flowCount})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate top talkers: %w", err)
	}
	return items, nil
}

func (r *FlowRepository) TopPorts(ctx context.Context, query AggregationQuery) ([]TopPortRow, error) {
	if err := validateAggregationQuery(query, true); err != nil {
		return nil, err
	}
	groupColumn := "src_port"
	if query.Direction == AggregationDirectionDst {
		groupColumn = "dst_port"
	}
	sqlQuery, args := buildAggregationSQL(query, groupColumn, groupColumn+" IS NOT NULL")
	rows, err := r.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query top ports: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	items := []TopPortRow{}
	for rows.Next() {
		var port int64
		var value uint64
		var flowCount uint64
		if err := rows.Scan(&port, &value, &flowCount); err != nil {
			return nil, fmt.Errorf("scan top port: %w", err)
		}
		parsedPort, err := checkedUint16("port", port)
		if err != nil {
			return nil, err
		}
		items = append(items, TopPortRow{Port: parsedPort, Metric: query.Metric, Value: value, FlowCount: flowCount})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate top ports: %w", err)
	}
	return items, nil
}

func (r *FlowRepository) ProtocolDistribution(ctx context.Context, query AggregationQuery) ([]ProtocolRow, error) {
	if err := validateAggregationQuery(query, false); err != nil {
		return nil, err
	}
	sqlQuery, args := buildAggregationSQL(query, "protocol_number, transport_protocol", "true")
	rows, err := r.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query protocol distribution: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	items := []ProtocolRow{}
	for rows.Next() {
		var protocolNumber int64
		var transportProtocol string
		var value uint64
		var flowCount uint64
		if err := rows.Scan(&protocolNumber, &transportProtocol, &value, &flowCount); err != nil {
			return nil, fmt.Errorf("scan protocol distribution: %w", err)
		}
		parsedProtocolNumber, err := checkedUint8("protocol_number", protocolNumber)
		if err != nil {
			return nil, err
		}
		items = append(items, ProtocolRow{
			ProtocolNumber:    parsedProtocolNumber,
			TransportProtocol: domain.TransportProtocol(transportProtocol),
			Metric:            query.Metric,
			Value:             value,
			FlowCount:         flowCount,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate protocol distribution: %w", err)
	}
	return items, nil
}

func insertArgs(record domain.NormalizedFlowRecord) []any {
	return []any{
		record.ID,
		record.SchemaVersion,
		record.IdempotencyKey,
		record.RawEventID,
		string(record.SourceType),
		record.CollectorID,
		record.SourceHost,
		nullableAddr(record.SourceIP),
		record.IngestedAt,
		record.NormalizedAt,
		record.EventStartTime,
		record.EventEndTime,
		record.DurationMS,
		record.SrcIP.String(),
		record.DstIP.String(),
		record.SrcPort,
		record.DstPort,
		record.IPVersion,
		string(record.TransportProtocol),
		record.ProtocolNumber,
		record.Bytes,
		record.Packets,
		record.TCPFlags,
		record.FlowState,
		string(record.Direction),
		record.InputInterface,
		record.OutputInterface,
		nullableAddr(record.NextHopIP),
		record.ApplicationProtocol,
		record.SamplingRate,
		string(record.NormalizationStatus),
		record.NormalizationError,
		jsonBytes(record.Attributes),
	}
}

func flowRecordColumns() string {
	return `id, schema_version, idempotency_key, raw_event_id,
source_type, collector_id, source_host, source_ip, ingested_at, normalized_at,
event_start_time, event_end_time, duration_ms,
src_ip, dst_ip, src_port, dst_port, ip_version, transport_protocol, protocol_number,
bytes, packets, tcp_flags, flow_state,
direction, input_interface, output_interface, next_hop_ip,
application_protocol, sampling_rate, normalization_status, normalization_error, attributes`
}

type scanner interface {
	Scan(dest ...any) error
}

func scanFlowRecord(row scanner) (domain.NormalizedFlowRecord, error) {
	var record domain.NormalizedFlowRecord
	var sourceType, transportProtocol, direction, normalizationStatus string
	var sourceIP, nextHopIP sql.NullString
	var eventEndTime sql.NullTime
	var durationMS, srcPort, dstPort, bytesValue, packets, tcpFlags sql.NullInt64
	var flowState, applicationProtocol, normalizationError sql.NullString
	var inputInterface, outputInterface, samplingRate sql.NullInt64
	var srcIP, dstIP string
	var protocolNumber int64
	var attrs []byte
	err := row.Scan(
		&record.ID,
		&record.SchemaVersion,
		&record.IdempotencyKey,
		&record.RawEventID,
		&sourceType,
		&record.CollectorID,
		&record.SourceHost,
		&sourceIP,
		&record.IngestedAt,
		&record.NormalizedAt,
		&record.EventStartTime,
		&eventEndTime,
		&durationMS,
		&srcIP,
		&dstIP,
		&srcPort,
		&dstPort,
		&record.IPVersion,
		&transportProtocol,
		&protocolNumber,
		&bytesValue,
		&packets,
		&tcpFlags,
		&flowState,
		&direction,
		&inputInterface,
		&outputInterface,
		&nextHopIP,
		&applicationProtocol,
		&samplingRate,
		&normalizationStatus,
		&normalizationError,
		&attrs,
	)
	if err != nil {
		return domain.NormalizedFlowRecord{}, fmt.Errorf("scan flow record: %w", err)
	}
	parsedSrc, err := netip.ParseAddr(srcIP)
	if err != nil {
		return domain.NormalizedFlowRecord{}, fmt.Errorf("parse src_ip: %w", err)
	}
	parsedDst, err := netip.ParseAddr(dstIP)
	if err != nil {
		return domain.NormalizedFlowRecord{}, fmt.Errorf("parse dst_ip: %w", err)
	}
	parsedProtocolNumber, err := checkedUint8("protocol_number", protocolNumber)
	if err != nil {
		return domain.NormalizedFlowRecord{}, err
	}
	record.SrcIP = parsedSrc
	record.DstIP = parsedDst
	record.ProtocolNumber = parsedProtocolNumber
	record.SourceType = domain.SourceType(sourceType)
	record.TransportProtocol = domain.TransportProtocol(transportProtocol)
	record.Direction = domain.Direction(direction)
	record.NormalizationStatus = domain.NormalizationStatus(normalizationStatus)
	record.EventEndTime = nullableTimePtr(eventEndTime)
	record.DurationMS = int64Ptr(durationMS)
	if record.SrcPort, err = uint16Ptr("src_port", srcPort); err != nil {
		return domain.NormalizedFlowRecord{}, err
	}
	if record.DstPort, err = uint16Ptr("dst_port", dstPort); err != nil {
		return domain.NormalizedFlowRecord{}, err
	}
	if record.Bytes, err = uint64Ptr("bytes", bytesValue); err != nil {
		return domain.NormalizedFlowRecord{}, err
	}
	if record.Packets, err = uint64Ptr("packets", packets); err != nil {
		return domain.NormalizedFlowRecord{}, err
	}
	if record.TCPFlags, err = uint16Ptr("tcp_flags", tcpFlags); err != nil {
		return domain.NormalizedFlowRecord{}, err
	}
	record.FlowState = stringPtr(flowState)
	if record.InputInterface, err = uint32Ptr("input_interface", inputInterface); err != nil {
		return domain.NormalizedFlowRecord{}, err
	}
	if record.OutputInterface, err = uint32Ptr("output_interface", outputInterface); err != nil {
		return domain.NormalizedFlowRecord{}, err
	}
	record.ApplicationProtocol = stringPtr(applicationProtocol)
	if record.SamplingRate, err = uint32Ptr("sampling_rate", samplingRate); err != nil {
		return domain.NormalizedFlowRecord{}, err
	}
	record.NormalizationError = stringPtr(normalizationError)
	if sourceIP.Valid {
		addr, err := netip.ParseAddr(sourceIP.String)
		if err != nil {
			return domain.NormalizedFlowRecord{}, fmt.Errorf("parse source_ip: %w", err)
		}
		record.SourceIP = &addr
	}
	if nextHopIP.Valid {
		addr, err := netip.ParseAddr(nextHopIP.String)
		if err != nil {
			return domain.NormalizedFlowRecord{}, fmt.Errorf("parse next_hop_ip: %w", err)
		}
		record.NextHopIP = &addr
	}
	if len(attrs) == 0 {
		record.Attributes = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(attrs, &record.Attributes); err != nil {
		return domain.NormalizedFlowRecord{}, fmt.Errorf("decode attributes: %w", err)
	}
	return record, nil
}

func buildFlowWhere(query FlowSearchQuery) (string, []any) {
	clauses := []string{"event_start_time >= $1", "event_start_time < $2"}
	args := []any{query.From, query.To}
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if query.SrcIP != nil {
		add("src_ip = $%d::inet", query.SrcIP.String())
	}
	if query.DstIP != nil {
		add("dst_ip = $%d::inet", query.DstIP.String())
	}
	if query.SrcCIDR != nil {
		add("src_ip <<= $%d::cidr", query.SrcCIDR.String())
	}
	if query.DstCIDR != nil {
		add("dst_ip <<= $%d::cidr", query.DstCIDR.String())
	}
	if query.SrcPort != nil {
		add("src_port = $%d", *query.SrcPort)
	}
	if query.DstPort != nil {
		add("dst_port = $%d", *query.DstPort)
	}
	if query.SrcPortRange != nil {
		args = append(args, query.SrcPortRange.From, query.SrcPortRange.To)
		clauses = append(clauses, fmt.Sprintf("src_port BETWEEN $%d AND $%d", len(args)-1, len(args)))
	}
	if query.DstPortRange != nil {
		args = append(args, query.DstPortRange.From, query.DstPortRange.To)
		clauses = append(clauses, fmt.Sprintf("dst_port BETWEEN $%d AND $%d", len(args)-1, len(args)))
	}
	if query.ProtocolNumber != nil {
		add("protocol_number = $%d", *query.ProtocolNumber)
	}
	if query.TransportProtocol != nil {
		add("transport_protocol = $%d", string(*query.TransportProtocol))
	}
	if query.SourceType != nil {
		add("source_type = $%d", string(*query.SourceType))
	}
	if query.CollectorID != "" {
		add("collector_id = $%d", query.CollectorID)
	}
	if query.SourceHost != "" {
		add("source_host = $%d", query.SourceHost)
	}
	if query.ApplicationProtocol != "" {
		add("application_protocol = $%d", query.ApplicationProtocol)
	}
	if query.Direction != nil {
		add("direction = $%d", string(*query.Direction))
	}
	if query.Cursor != nil {
		args = append(args, query.Cursor.EventStartTime, query.Cursor.ID)
		clauses = append(
			clauses,
			fmt.Sprintf(
				"(event_start_time < $%d OR (event_start_time = $%d AND id < $%d::uuid))",
				len(args)-1,
				len(args)-1,
				len(args),
			),
		)
	}
	return strings.Join(clauses, " AND "), args
}

func buildAggregationSQL(query AggregationQuery, groupExpr string, extraPredicate string) (string, []any) {
	valueExpr := "SUM(bytes)"
	nullPredicate := "bytes IS NOT NULL"
	switch query.Metric {
	case AggregationMetricPackets:
		valueExpr = "SUM(packets)"
		nullPredicate = "packets IS NOT NULL"
	case AggregationMetricFlows:
		valueExpr = "COUNT(*)"
		nullPredicate = "true"
	}
	clauses := []string{"event_start_time >= $1", "event_start_time < $2", nullPredicate, extraPredicate}
	args := []any{query.From, query.To}
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if query.SrcIP != nil {
		add("src_ip = $%d::inet", query.SrcIP.String())
	}
	if query.DstIP != nil {
		add("dst_ip = $%d::inet", query.DstIP.String())
	}
	if query.ProtocolNumber != nil {
		add("protocol_number = $%d", *query.ProtocolNumber)
	}
	if query.SourceType != nil {
		add("source_type = $%d", string(*query.SourceType))
	}
	args = append(args, query.Limit)
	return `SELECT ` + groupExpr + `, ` + valueExpr + ` AS value, COUNT(*) AS flow_count
FROM quiver.flow_records
WHERE ` + strings.Join(clauses, " AND ") + `
GROUP BY ` + groupExpr + `
ORDER BY value DESC, flow_count DESC
LIMIT $` + fmt.Sprint(len(args)), args
}

func validateSearchQuery(query FlowSearchQuery) error {
	if query.From.IsZero() || query.To.IsZero() || !query.From.Before(query.To) {
		return fmt.Errorf("%w: invalid time range", ErrInvalidFlowQuery)
	}
	if query.Limit <= 0 {
		return fmt.Errorf("%w: limit must be positive", ErrInvalidFlowQuery)
	}
	return nil
}

func validateAggregationQuery(query AggregationQuery, requireDirection bool) error {
	if query.From.IsZero() || query.To.IsZero() || !query.From.Before(query.To) {
		return fmt.Errorf("%w: invalid time range", ErrInvalidFlowQuery)
	}
	if query.Limit <= 0 {
		return fmt.Errorf("%w: limit must be positive", ErrInvalidFlowQuery)
	}
	switch query.Metric {
	case AggregationMetricBytes, AggregationMetricPackets, AggregationMetricFlows:
	default:
		return fmt.Errorf("%w: invalid metric", ErrInvalidFlowQuery)
	}
	if requireDirection && query.Direction != AggregationDirectionSrc && query.Direction != AggregationDirectionDst {
		return fmt.Errorf("%w: invalid direction", ErrInvalidFlowQuery)
	}
	return nil
}

func nullableAddr(addr *netip.Addr) any {
	if addr == nil {
		return nil
	}
	return addr.String()
}

func jsonBytes(attrs map[string]json.RawMessage) []byte {
	if attrs == nil {
		return []byte(`{}`)
	}
	data, err := json.Marshal(attrs)
	if err != nil {
		return []byte(`{}`)
	}
	return data
}

func nullableTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	return &value.Time
}

func int64Ptr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	return &value.Int64
}

func uint16Ptr(field string, value sql.NullInt64) (*uint16, error) {
	if !value.Valid {
		return nil, nil
	}
	converted, err := checkedUint16(field, value.Int64)
	if err != nil {
		return nil, err
	}
	return &converted, nil
}

func uint32Ptr(field string, value sql.NullInt64) (*uint32, error) {
	if !value.Valid {
		return nil, nil
	}
	if value.Int64 < 0 || value.Int64 > int64(^uint32(0)) {
		return nil, fmt.Errorf("scan flow record: %s out of range", field)
	}
	converted := uint32(value.Int64)
	return &converted, nil
}

func uint64Ptr(field string, value sql.NullInt64) (*uint64, error) {
	if !value.Valid {
		return nil, nil
	}
	if value.Int64 < 0 {
		return nil, fmt.Errorf("scan flow record: %s out of range", field)
	}
	converted := uint64(value.Int64)
	return &converted, nil
}

func stringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}

func checkedUint8(field string, value int64) (uint8, error) {
	if value < 0 || value > 255 {
		return 0, fmt.Errorf("scan flow record: %s out of range", field)
	}
	return uint8(value), nil
}

func checkedUint16(field string, value int64) (uint16, error) {
	if value < 0 || value > 65535 {
		return 0, fmt.Errorf("scan flow record: %s out of range", field)
	}
	return uint16(value), nil
}
