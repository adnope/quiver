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

type AggregationEndpoint string

const (
	AggregationEndpointProtocols  AggregationEndpoint = "protocols"
	AggregationEndpointTopPorts   AggregationEndpoint = "top-ports"
	AggregationEndpointTopTalkers AggregationEndpoint = "top-talkers"

	flowAggregationFiveMinuteMaxWindow = 6 * time.Hour
)

type AggregationCursor struct {
	Endpoint          AggregationEndpoint
	QueryHash         string
	Metric            AggregationMetric
	Direction         AggregationDirection
	Value             uint64
	FlowCount         uint64
	IP                *netip.Addr
	Port              *uint16
	ProtocolNumber    *uint8
	TransportProtocol *domain.TransportProtocol
}

type AggregationQuery struct {
	From           time.Time
	To             time.Time
	Metric         AggregationMetric
	Limit          int
	Direction      AggregationDirection
	Cursor         *AggregationCursor
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

func (r *FlowRepository) DB() *sql.DB {
	if r == nil {
		return nil
	}
	return r.db
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
			return InsertResult{}, fmt.Errorf("%w: record %d: %w", ErrInvalidFlowQuery, i, err)
		}
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return InsertResult{}, fmt.Errorf("begin flow insert transaction: %w", err)
	}

	const maxRecordsPerChunk = 2000

	var totalInserted int64

	for startIdx := 0; startIdx < len(records); startIdx += maxRecordsPerChunk {
		endIdx := min(startIdx+maxRecordsPerChunk, len(records))
		chunk := records[startIdx:endIdx]

		n := len(chunk)
		ids := make([]string, n)
		schemaVersions := make([]string, n)
		idempotencyKeys := make([]string, n)
		rawEventIDs := make([]string, n)
		sourceTypes := make([]string, n)
		collectorIDs := make([]string, n)
		sourceHosts := make([]string, n)
		sourceIPs := make([]*string, n)
		ingestedAts := make([]time.Time, n)
		normalizedAts := make([]time.Time, n)
		eventStartTimes := make([]time.Time, n)
		eventEndTimes := make([]*time.Time, n)
		durationMSs := make([]*int64, n)
		srcIPs := make([]string, n)
		dstIPs := make([]string, n)
		srcPorts := make([]*int32, n)
		dstPorts := make([]*int32, n)
		ipVersions := make([]int16, n)
		transportProtocols := make([]string, n)
		protocolNumbers := make([]int16, n)
		bytesSlice := make([]*int64, n)
		packetsSlice := make([]*int64, n)
		tcpFlagsSlice := make([]*int32, n)
		flowStates := make([]*string, n)
		directions := make([]string, n)
		inputInterfaces := make([]*int32, n)
		outputInterfaces := make([]*int32, n)
		nextHopIPs := make([]*string, n)
		applicationProtocols := make([]*string, n)
		samplingRates := make([]*int32, n)
		normalizationStatuses := make([]string, n)
		normalizationErrors := make([]*string, n)
		attributesSlice := make([]string, n)

		for i, rec := range chunk {
			ids[i] = rec.ID
			schemaVersions[i] = rec.SchemaVersion
			idempotencyKeys[i] = rec.IdempotencyKey
			rawEventIDs[i] = rec.RawEventID
			sourceTypes[i] = string(rec.SourceType)
			collectorIDs[i] = rec.CollectorID
			sourceHosts[i] = rec.SourceHost
			if rec.SourceIP != nil {
				ipStr := rec.SourceIP.String()
				sourceIPs[i] = &ipStr
			}
			ingestedAts[i] = rec.IngestedAt
			normalizedAts[i] = rec.NormalizedAt
			eventStartTimes[i] = rec.EventStartTime
			if rec.EventEndTime != nil {
				t := *rec.EventEndTime
				eventEndTimes[i] = &t
			}
			durationMSs[i] = rec.DurationMS
			srcIPs[i] = rec.SrcIP.String()
			dstIPs[i] = rec.DstIP.String()
			if rec.SrcPort != nil {
				portVal := int32(*rec.SrcPort)
				srcPorts[i] = &portVal
			}
			if rec.DstPort != nil {
				portVal := int32(*rec.DstPort)
				dstPorts[i] = &portVal
			}
			ipVersions[i] = int16(rec.IPVersion) //nolint:gosec
			transportProtocols[i] = string(rec.TransportProtocol)
			protocolNumbers[i] = int16(rec.ProtocolNumber)
			if rec.Bytes != nil {
				val := int64(*rec.Bytes) //nolint:gosec
				bytesSlice[i] = &val
			}
			if rec.Packets != nil {
				val := int64(*rec.Packets) //nolint:gosec
				packetsSlice[i] = &val
			}
			if rec.TCPFlags != nil {
				val := int32(*rec.TCPFlags)
				tcpFlagsSlice[i] = &val
			}
			flowStates[i] = rec.FlowState
			directions[i] = string(rec.Direction)
			if rec.InputInterface != nil {
				val := int32(*rec.InputInterface) //nolint:gosec
				inputInterfaces[i] = &val
			}
			if rec.OutputInterface != nil {
				val := int32(*rec.OutputInterface) //nolint:gosec
				outputInterfaces[i] = &val
			}
			if rec.NextHopIP != nil {
				ipStr := rec.NextHopIP.String()
				nextHopIPs[i] = &ipStr
			}
			applicationProtocols[i] = rec.ApplicationProtocol
			if rec.SamplingRate != nil {
				val := int32(*rec.SamplingRate) //nolint:gosec
				samplingRates[i] = &val
			}
			normalizationStatuses[i] = string(rec.NormalizationStatus)
			normalizationErrors[i] = rec.NormalizationError
			attributesSlice[i] = string(jsonBytes(rec.Attributes))
		}

		query := `INSERT INTO quiver.flow_records (
id, schema_version, idempotency_key, raw_event_id,
source_type, collector_id, source_host, source_ip, ingested_at, normalized_at,
event_start_time, event_end_time, duration_ms,
src_ip, dst_ip, src_port, dst_port, ip_version, transport_protocol, protocol_number,
bytes, packets, tcp_flags, flow_state,
direction, input_interface, output_interface, next_hop_ip,
application_protocol, sampling_rate, normalization_status, normalization_error, attributes
) SELECT * FROM UNNEST(
$1::text[]::uuid[], $2::text[], $3::text[], $4::text[]::uuid[],
$5::text[], $6::text[], $7::text[], $8::text[]::inet[], $9::timestamptz[], $10::timestamptz[],
$11::timestamptz[], $12::timestamptz[], $13::bigint[],
$14::text[]::inet[], $15::text[]::inet[], $16::integer[], $17::integer[], $18::smallint[], $19::text[], $20::smallint[],
$21::bigint[], $22::bigint[], $23::integer[], $24::text[],
$25::text[], $26::integer[], $27::integer[], $28::text[]::inet[],
$29::text[], $30::integer[], $31::text[], $32::text[], $33::text[]::jsonb[]
) ON CONFLICT (event_start_time, idempotency_key) DO NOTHING`

		result, execErr := tx.ExecContext(ctx, query,
			ids, schemaVersions, idempotencyKeys, rawEventIDs,
			sourceTypes, collectorIDs, sourceHosts, sourceIPs, ingestedAts, normalizedAts,
			eventStartTimes, eventEndTimes, durationMSs,
			srcIPs, dstIPs, srcPorts, dstPorts, ipVersions, transportProtocols, protocolNumbers,
			bytesSlice, packetsSlice, tcpFlagsSlice, flowStates,
			directions, inputInterfaces, outputInterfaces, nextHopIPs,
			applicationProtocols, samplingRates, normalizationStatuses, normalizationErrors, attributesSlice,
		)
		if execErr != nil {
			_ = tx.Rollback()
			return InsertResult{}, fmt.Errorf("insert flow records unnest: %w", execErr)
		}

		inserted, err := result.RowsAffected()
		if err != nil {
			_ = tx.Rollback()
			return InsertResult{}, fmt.Errorf("read inserted flow row count: %w", err)
		}
		totalInserted += inserted
	}

	if err := tx.Commit(); err != nil {
		return InsertResult{}, fmt.Errorf("commit flow insert transaction: %w", err)
	}

	return InsertResult{
		Attempted:    len(records),
		Inserted:     int(totalInserted),
		Deduplicated: len(records) - int(totalInserted),
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
	sqlQuery := `SELECT ` + flowRecordColumns + `
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

func (r *FlowRepository) GetFlowByID(ctx context.Context, id string, eventStartTime *time.Time) (domain.NormalizedFlowRecord, bool, error) {
	if !domain.IsUUIDv7(id) {
		return domain.NormalizedFlowRecord{}, false, fmt.Errorf("%w: id must be uuidv7", ErrInvalidFlowQuery)
	}
	// security: selected columns are a fixed internal list; id remains parameterized.
	// #nosec G202
	var row *sql.Row
	if eventStartTime != nil {
		row = r.db.QueryRowContext(
			ctx,
			`SELECT `+flowRecordColumns+`
FROM quiver.flow_records
WHERE event_start_time = $1 AND id = $2
LIMIT 1`,
			*eventStartTime,
			id,
		)
	} else {
		row = r.db.QueryRowContext(
			ctx,
			`SELECT `+flowRecordColumns+`
FROM quiver.flow_records
WHERE id = $1
LIMIT 1`,
			id,
		)
	}
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
	if err := validateAggregationCursor(query, AggregationEndpointTopTalkers); err != nil {
		return nil, err
	}
	groupColumn := "src_ip"
	if query.Direction == AggregationDirectionDst {
		groupColumn = "dst_ip"
	}
	sqlQuery, args, err := buildAggregationSQL(query, aggregationGrouping{
		Select:  groupColumn + " AS ip",
		GroupBy: groupColumn,
		OrderBy: "ip ASC",
		Kind:    aggregationGroupIP,
	}, aggregateTalkersTable(query), "true")
	if err != nil {
		return nil, err
	}
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
	if err := validateAggregationCursor(query, AggregationEndpointTopPorts); err != nil {
		return nil, err
	}
	groupColumn := "src_port"
	if query.Direction == AggregationDirectionDst {
		groupColumn = "dst_port"
	}
	targetTable := aggregatePortsTable(query)
	sqlQuery, args, err := buildAggregationSQL(query, aggregationGrouping{
		Select:  groupColumn + " AS port",
		GroupBy: groupColumn,
		OrderBy: "port ASC",
		Kind:    aggregationGroupPort,
	}, targetTable, groupColumn+" IS NOT NULL")
	if err != nil {
		return nil, err
	}
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
	if err := validateAggregationCursor(query, AggregationEndpointProtocols); err != nil {
		return nil, err
	}
	sqlQuery, args, err := buildAggregationSQL(query, aggregationGrouping{
		Select:  "protocol_number, transport_protocol",
		GroupBy: "protocol_number, transport_protocol",
		OrderBy: "protocol_number ASC, transport_protocol ASC",
		Kind:    aggregationGroupProtocol,
	}, aggregateTalkersTable(query), "true")
	if err != nil {
		return nil, err
	}
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

const flowRecordColumns = `id, schema_version, idempotency_key, raw_event_id,
source_type, collector_id, source_host, source_ip, ingested_at, normalized_at,
event_start_time, event_end_time, duration_ms,
src_ip, dst_ip, src_port, dst_port, ip_version, transport_protocol, protocol_number,
bytes, packets, tcp_flags, flow_state,
direction, input_interface, output_interface, next_hop_ip,
application_protocol, sampling_rate, normalization_status, normalization_error, attributes`

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
	if record.SrcPort, err = uint16Ptr("src_port", srcPort); err != nil && !errors.Is(err, errSQLNullValue) {
		return domain.NormalizedFlowRecord{}, err
	}
	if record.DstPort, err = uint16Ptr("dst_port", dstPort); err != nil && !errors.Is(err, errSQLNullValue) {
		return domain.NormalizedFlowRecord{}, err
	}
	if record.Bytes, err = uint64Ptr("bytes", bytesValue); err != nil && !errors.Is(err, errSQLNullValue) {
		return domain.NormalizedFlowRecord{}, err
	}
	if record.Packets, err = uint64Ptr("packets", packets); err != nil && !errors.Is(err, errSQLNullValue) {
		return domain.NormalizedFlowRecord{}, err
	}
	if record.TCPFlags, err = uint16Ptr("tcp_flags", tcpFlags); err != nil && !errors.Is(err, errSQLNullValue) {
		return domain.NormalizedFlowRecord{}, err
	}
	record.FlowState = stringPtr(flowState)
	if record.InputInterface, err = uint32Ptr("input_interface", inputInterface); err != nil && !errors.Is(err, errSQLNullValue) {
		return domain.NormalizedFlowRecord{}, err
	}
	if record.OutputInterface, err = uint32Ptr("output_interface", outputInterface); err != nil && !errors.Is(err, errSQLNullValue) {
		return domain.NormalizedFlowRecord{}, err
	}
	record.ApplicationProtocol = stringPtr(applicationProtocol)
	if record.SamplingRate, err = uint32Ptr("sampling_rate", samplingRate); err != nil && !errors.Is(err, errSQLNullValue) {
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

func aggregateTalkersTable(query AggregationQuery) string {
	return selectFlowAggregateTable(query, "quiver.flow_5m_talkers", "quiver.flow_hourly_talkers")
}

func aggregatePortsTable(query AggregationQuery) string {
	if query.SrcIP != nil || query.DstIP != nil {
		return "quiver.flow_records"
	}
	return selectFlowAggregateTable(query, "quiver.flow_5m_ports", "quiver.flow_hourly_ports")
}

func selectFlowAggregateTable(query AggregationQuery, fiveMinuteTable string, hourlyTable string) string {
	if query.To.Sub(query.From) <= flowAggregationFiveMinuteMaxWindow {
		return fiveMinuteTable
	}
	return hourlyTable
}

type aggregationGroupKind string

const (
	aggregationGroupIP       aggregationGroupKind = "ip"
	aggregationGroupPort     aggregationGroupKind = "port"
	aggregationGroupProtocol aggregationGroupKind = "protocol"
)

type aggregationGrouping struct {
	Select  string
	GroupBy string
	OrderBy string
	Kind    aggregationGroupKind
}

func buildAggregationSQL(query AggregationQuery, grouping aggregationGrouping, targetTable string, extraPredicate string) (string, []any, error) {
	timeCol := "bucket"
	valueExpr := "SUM(bytes)"
	nullPredicate := "bytes IS NOT NULL"

	if targetTable == "quiver.flow_records" {
		timeCol = "event_start_time"
		switch query.Metric {
		case AggregationMetricBytes:
			valueExpr = "SUM(bytes)"
			nullPredicate = "bytes IS NOT NULL"
		case AggregationMetricPackets:
			valueExpr = "SUM(packets)"
			nullPredicate = "packets IS NOT NULL"
		case AggregationMetricFlows:
			valueExpr = "COUNT(*)"
			nullPredicate = "true"
		}
	} else {
		switch query.Metric {
		case AggregationMetricBytes:
			valueExpr = "SUM(bytes)"
			nullPredicate = "bytes IS NOT NULL"
		case AggregationMetricPackets:
			valueExpr = "SUM(packets)"
			nullPredicate = "packets IS NOT NULL"
		case AggregationMetricFlows:
			valueExpr = "SUM(flow_count)"
			nullPredicate = "true"
		}
	}

	clauses := []string{timeCol + " >= $1", timeCol + " < $2", nullPredicate, extraPredicate}
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

	flowsSelect := "SUM(flow_count) AS flow_count"
	if targetTable == "quiver.flow_records" {
		flowsSelect = "COUNT(*) AS flow_count"
	}

	cursorPredicate, err := buildAggregationCursorPredicate(&args, query.Cursor, grouping.Kind)
	if err != nil {
		return "", nil, err
	}
	args = append(args, query.Limit)
	limitPlaceholder := fmt.Sprintf("$%d", len(args))

	outerWhere := ""
	if cursorPredicate != "" {
		outerWhere = "\nWHERE " + cursorPredicate
	}

	return `SELECT *
FROM (
	SELECT ` + grouping.Select + `, ` + valueExpr + ` AS value, ` + flowsSelect + `
	FROM ` + targetTable + `
	WHERE ` + strings.Join(clauses, " AND ") + `
	GROUP BY ` + grouping.GroupBy + `
) agg` + outerWhere + `
ORDER BY value DESC, flow_count DESC, ` + grouping.OrderBy + `
LIMIT ` + limitPlaceholder, args, nil
}

func buildAggregationCursorPredicate(args *[]any, cursor *AggregationCursor, kind aggregationGroupKind) (string, error) {
	if cursor == nil {
		return "", nil
	}
	add := func(value any) int {
		*args = append(*args, value)
		return len(*args)
	}
	valueArg := add(cursor.Value)
	flowCountArg := add(cursor.FlowCount)

	switch kind {
	case aggregationGroupIP:
		if cursor.IP == nil {
			return "", fmt.Errorf("%w: aggregation cursor missing ip", ErrInvalidFlowQuery)
		}
		ipArg := add(cursor.IP.String())
		return fmt.Sprintf(
			"(value < $%d OR (value = $%d AND flow_count < $%d) OR (value = $%d AND flow_count = $%d AND ip > $%d::inet))",
			valueArg, valueArg, flowCountArg, valueArg, flowCountArg, ipArg,
		), nil
	case aggregationGroupPort:
		if cursor.Port == nil {
			return "", fmt.Errorf("%w: aggregation cursor missing port", ErrInvalidFlowQuery)
		}
		portArg := add(*cursor.Port)
		return fmt.Sprintf(
			"(value < $%d OR (value = $%d AND flow_count < $%d) OR (value = $%d AND flow_count = $%d AND port > $%d))",
			valueArg, valueArg, flowCountArg, valueArg, flowCountArg, portArg,
		), nil
	case aggregationGroupProtocol:
		if cursor.ProtocolNumber == nil || cursor.TransportProtocol == nil {
			return "", fmt.Errorf("%w: aggregation cursor missing protocol key", ErrInvalidFlowQuery)
		}
		protocolNumberArg := add(*cursor.ProtocolNumber)
		transportProtocolArg := add(string(*cursor.TransportProtocol))
		return fmt.Sprintf(
			"(value < $%d OR (value = $%d AND flow_count < $%d) OR (value = $%d AND flow_count = $%d AND (protocol_number > $%d OR (protocol_number = $%d AND transport_protocol > $%d))))",
			valueArg, valueArg, flowCountArg, valueArg, flowCountArg, protocolNumberArg, protocolNumberArg, transportProtocolArg,
		), nil
	default:
		return "", fmt.Errorf("%w: invalid aggregation group", ErrInvalidFlowQuery)
	}
}

func validateAggregationCursor(query AggregationQuery, endpoint AggregationEndpoint) error {
	if query.Cursor == nil {
		return nil
	}
	cursor := query.Cursor
	if cursor.Endpoint != endpoint {
		return fmt.Errorf("%w: aggregation cursor endpoint mismatch", ErrInvalidFlowQuery)
	}
	if cursor.Metric != query.Metric {
		return fmt.Errorf("%w: aggregation cursor metric mismatch", ErrInvalidFlowQuery)
	}
	if endpoint != AggregationEndpointProtocols && cursor.Direction != query.Direction {
		return fmt.Errorf("%w: aggregation cursor direction mismatch", ErrInvalidFlowQuery)
	}
	switch endpoint {
	case AggregationEndpointTopTalkers:
		if cursor.IP == nil {
			return fmt.Errorf("%w: aggregation cursor missing ip", ErrInvalidFlowQuery)
		}
	case AggregationEndpointTopPorts:
		if cursor.Port == nil {
			return fmt.Errorf("%w: aggregation cursor missing port", ErrInvalidFlowQuery)
		}
	case AggregationEndpointProtocols:
		if cursor.ProtocolNumber == nil || cursor.TransportProtocol == nil {
			return fmt.Errorf("%w: aggregation cursor missing protocol key", ErrInvalidFlowQuery)
		}
	default:
		return fmt.Errorf("%w: invalid aggregation endpoint", ErrInvalidFlowQuery)
	}
	return nil
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

var errSQLNullValue = errors.New("sql value is null")

func uint16Ptr(field string, value sql.NullInt64) (*uint16, error) {
	if !value.Valid {
		return nil, errSQLNullValue
	}
	converted, err := checkedUint16(field, value.Int64)
	if err != nil {
		return nil, err
	}
	return &converted, nil
}

func uint32Ptr(field string, value sql.NullInt64) (*uint32, error) {
	if !value.Valid {
		return nil, errSQLNullValue
	}
	if value.Int64 < 0 || value.Int64 > int64(^uint32(0)) {
		return nil, fmt.Errorf("scan flow record: %s out of range", field)
	}
	converted := uint32(value.Int64)
	return &converted, nil
}

func uint64Ptr(field string, value sql.NullInt64) (*uint64, error) {
	if !value.Valid {
		return nil, errSQLNullValue
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
