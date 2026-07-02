package postgres

import (
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAggregateTalkersTableRoutesByWindow(t *testing.T) {
	t.Parallel()

	from := time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		to   time.Time
		want string
	}{
		{
			name: "short window uses five minute talkers",
			to:   from.Add(2 * time.Hour),
			want: "quiver.flow_5m_talkers",
		},
		{
			name: "six hour boundary uses five minute talkers",
			to:   from.Add(6 * time.Hour),
			want: "quiver.flow_5m_talkers",
		},
		{
			name: "long window uses hourly talkers",
			to:   from.Add(6*time.Hour + time.Nanosecond),
			want: "quiver.flow_hourly_talkers",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := aggregateTalkersTable(AggregationQuery{From: from, To: tc.to})
			if got != tc.want {
				t.Fatalf("aggregateTalkersTable() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAggregatePortsTableRoutesByWindowAndRawFallback(t *testing.T) {
	t.Parallel()

	from := time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)
	srcIP := netip.MustParseAddr("192.168.1.10")
	tests := []struct {
		name  string
		query AggregationQuery
		want  string
	}{
		{
			name: "short window uses five minute ports",
			query: AggregationQuery{
				From: from,
				To:   from.Add(2 * time.Hour),
			},
			want: "quiver.flow_5m_ports",
		},
		{
			name: "long window uses hourly ports",
			query: AggregationQuery{
				From: from,
				To:   from.Add(24 * time.Hour),
			},
			want: "quiver.flow_hourly_ports",
		},
		{
			name: "ip filtered ports fall back to raw records",
			query: AggregationQuery{
				From:  from,
				To:    from.Add(2 * time.Hour),
				SrcIP: &srcIP,
			},
			want: "quiver.flow_records",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := aggregatePortsTable(tc.query)
			if got != tc.want {
				t.Fatalf("aggregatePortsTable() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildAggregationSQLUsesCAGGBucketOrRawTimestamp(t *testing.T) {
	t.Parallel()

	from := time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)
	query := AggregationQuery{
		From:   from,
		To:     from.Add(time.Hour),
		Metric: AggregationMetricFlows,
		Limit:  10,
	}
	grouping := aggregationGrouping{
		Select:  "protocol_number, transport_protocol",
		GroupBy: "protocol_number, transport_protocol",
		OrderBy: "protocol_number ASC, transport_protocol ASC",
		Kind:    aggregationGroupProtocol,
	}

	caggSQL, _, err := buildAggregationSQL(query, grouping, aggregateTalkersTable(query), "true")
	if err != nil {
		t.Fatalf("build cagg SQL: %v", err)
	}
	requireContains(t, caggSQL, "FROM quiver.flow_5m_talkers")
	requireContains(t, caggSQL, "bucket >= $1")
	requireContains(t, caggSQL, "SUM(flow_count) AS value")

	rawSQL, _, err := buildAggregationSQL(query, grouping, "quiver.flow_records", "true")
	if err != nil {
		t.Fatalf("build raw SQL: %v", err)
	}
	requireContains(t, rawSQL, "FROM quiver.flow_records")
	requireContains(t, rawSQL, "event_start_time >= $1")
	requireContains(t, rawSQL, "COUNT(*) AS value")
}

func TestRefreshContinuousAggregateQueryAllowsAllFlowAggregateViews(t *testing.T) {
	t.Parallel()

	for _, view := range []string{
		"quiver.flow_5m_talkers",
		"quiver.flow_5m_ports",
		"quiver.flow_hourly_talkers",
		"quiver.flow_hourly_ports",
	} {
		t.Run(view, func(t *testing.T) {
			t.Parallel()

			query, err := refreshContinuousAggregateQuery(view)
			if err != nil {
				t.Fatalf("refreshContinuousAggregateQuery(%q): %v", view, err)
			}
			requireContains(t, query, "CALL refresh_continuous_aggregate('")
			requireContains(t, query, view)
		})
	}
}

func TestRefreshContinuousAggregateQueryRejectsUnknownView(t *testing.T) {
	t.Parallel()

	if _, err := refreshContinuousAggregateQuery("quiver.flow_daily_talkers"); err == nil {
		t.Fatal("expected unsupported continuous aggregate error")
	}
}

func requireContains(t *testing.T, haystack string, needle string) {
	t.Helper()

	if !strings.Contains(haystack, needle) {
		t.Fatalf("expected %q to contain %q", haystack, needle)
	}
}

func TestFlowRepository_Helpers(t *testing.T) {
	t.Parallel()

	// 1. nullableTimePtr
	var nt sql.NullTime
	if got := nullableTimePtr(nt); got != nil {
		t.Errorf("expected nil time pointer, got %v", got)
	}
	nt.Valid = true
	now := time.Now()
	nt.Time = now
	if got := nullableTimePtr(nt); got == nil || *got != now {
		t.Errorf("expected %v, got %v", now, got)
	}

	// 2. int64Ptr
	var nInt sql.NullInt64
	if got := int64Ptr(nInt); got != nil {
		t.Errorf("expected nil int64 pointer, got %v", got)
	}
	nInt.Valid = true
	nInt.Int64 = 42
	if got := int64Ptr(nInt); got == nil || *got != 42 {
		t.Errorf("expected 42, got %v", got)
	}

	// 3. uint16Ptr
	var nInt16 sql.NullInt64
	if got, err := uint16Ptr("f", nInt16); !errors.Is(err, errSQLNullValue) || got != nil {
		t.Error("expected error for invalid NullInt64")
	}
	nInt16.Valid = true
	nInt16.Int64 = -1
	if _, err := uint16Ptr("f", nInt16); err == nil {
		t.Error("expected error for negative uint16 value")
	}
	nInt16.Int64 = 999999
	if _, err := uint16Ptr("f", nInt16); err == nil {
		t.Error("expected error for overflow uint16 value")
	}
	nInt16.Int64 = 100
	if got, err := uint16Ptr("f", nInt16); err != nil || got == nil || *got != 100 {
		t.Errorf("expected 100, got %v, err %v", got, err)
	}

	// 4. uint32Ptr
	var nInt32 sql.NullInt64
	if got, err := uint32Ptr("f", nInt32); !errors.Is(err, errSQLNullValue) || got != nil {
		t.Error("expected error for invalid NullInt64")
	}
	nInt32.Valid = true
	nInt32.Int64 = -1
	if _, err := uint32Ptr("f", nInt32); err == nil {
		t.Error("expected error for negative uint32 value")
	}
	nInt32.Int64 = 99999999999999
	if _, err := uint32Ptr("f", nInt32); err == nil {
		t.Error("expected error for overflow uint32 value")
	}
	nInt32.Int64 = 100
	if got, err := uint32Ptr("f", nInt32); err != nil || got == nil || *got != 100 {
		t.Errorf("expected 100, got %v, err %v", got, err)
	}

	// 5. uint64Ptr
	var nInt64 sql.NullInt64
	if got, err := uint64Ptr("f", nInt64); !errors.Is(err, errSQLNullValue) || got != nil {
		t.Error("expected error for invalid NullInt64")
	}
	nInt64.Valid = true
	nInt64.Int64 = -1
	if _, err := uint64Ptr("f", nInt64); err == nil {
		t.Error("expected error for negative uint64 value")
	}
	nInt64.Int64 = 100
	if got, err := uint64Ptr("f", nInt64); err != nil || got == nil || *got != 100 {
		t.Errorf("expected 100, got %v, err %v", got, err)
	}

	// 6. stringPtr
	var nStr sql.NullString
	if got := stringPtr(nStr); got != nil {
		t.Errorf("expected nil string pointer, got %v", got)
	}
	nStr.Valid = true
	nStr.String = "hello"
	if got := stringPtr(nStr); got == nil || *got != "hello" {
		t.Errorf("expected 'hello', got %v", got)
	}

	// 7. checkedUint8
	if _, err := checkedUint8("f", -1); err == nil {
		t.Error("expected error for negative uint8")
	}
	if _, err := checkedUint8("f", 256); err == nil {
		t.Error("expected error for overflow uint8")
	}

	// 8. checkedUint16
	if _, err := checkedUint16("f", -1); err == nil {
		t.Error("expected error for negative uint16")
	}
	if _, err := checkedUint16("f", 65536); err == nil {
		t.Error("expected error for overflow uint16")
	}
}

func TestFlowRepository_CursorValidation(t *testing.T) {
	t.Parallel()

	// 1. buildAggregationCursorPredicate with nil cursor
	sqlStr, err := buildAggregationCursorPredicate(nil, nil, aggregationGroupIP)
	if err != nil || sqlStr != "" {
		t.Errorf("expected empty string and nil error for nil cursor, got %q, %v", sqlStr, err)
	}

	// 2. buildAggregationCursorPredicate missing ip
	var args []any
	cursor := &AggregationCursor{Value: 10, FlowCount: 5}
	_, err = buildAggregationCursorPredicate(&args, cursor, aggregationGroupIP)
	if err == nil || !strings.Contains(err.Error(), "missing ip") {
		t.Errorf("expected missing ip error, got %v", err)
	}

	// 3. buildAggregationCursorPredicate missing port
	_, err = buildAggregationCursorPredicate(&args, cursor, aggregationGroupPort)
	if err == nil || !strings.Contains(err.Error(), "missing port") {
		t.Errorf("expected missing port error, got %v", err)
	}

	// 4. buildAggregationCursorPredicate missing protocol
	_, err = buildAggregationCursorPredicate(&args, cursor, aggregationGroupProtocol)
	if err == nil || !strings.Contains(err.Error(), "missing protocol key") {
		t.Errorf("expected missing protocol key error, got %v", err)
	}

	// 5. buildAggregationCursorPredicate invalid group
	_, err = buildAggregationCursorPredicate(&args, cursor, aggregationGroupKind("invalid"))
	if err == nil || !strings.Contains(err.Error(), "invalid aggregation group") {
		t.Errorf("expected invalid aggregation group error, got %v", err)
	}

	// 6. validateAggregationCursor nil cursor
	query := AggregationQuery{Cursor: nil}
	err = validateAggregationCursor(query, AggregationEndpointTopTalkers)
	if err != nil {
		t.Errorf("expected nil error for nil cursor in validation, got %v", err)
	}

	// 7. validateAggregationCursor endpoint mismatch
	cursor = &AggregationCursor{Endpoint: AggregationEndpointTopPorts, Metric: AggregationMetricFlows}
	query.Cursor = cursor
	err = validateAggregationCursor(query, AggregationEndpointTopTalkers)
	if err == nil || !strings.Contains(err.Error(), "endpoint mismatch") {
		t.Errorf("expected endpoint mismatch error, got %v", err)
	}

	// 8. validateAggregationCursor metric mismatch
	cursor.Endpoint = AggregationEndpointTopTalkers
	cursor.Metric = AggregationMetricBytes
	query.Metric = AggregationMetricFlows
	err = validateAggregationCursor(query, AggregationEndpointTopTalkers)
	if err == nil || !strings.Contains(err.Error(), "metric mismatch") {
		t.Errorf("expected metric mismatch error, got %v", err)
	}

	// 9. validateAggregationCursor direction mismatch
	cursor.Metric = AggregationMetricFlows
	cursor.Direction = AggregationDirectionSrc
	query.Direction = AggregationDirectionDst
	err = validateAggregationCursor(query, AggregationEndpointTopTalkers)
	if err == nil || !strings.Contains(err.Error(), "direction mismatch") {
		t.Errorf("expected direction mismatch error, got %v", err)
	}

	// 10. validateAggregationCursor missing ip
	cursor.Direction = AggregationDirectionDst
	cursor.IP = nil
	err = validateAggregationCursor(query, AggregationEndpointTopTalkers)
	if err == nil || !strings.Contains(err.Error(), "missing ip") {
		t.Errorf("expected missing ip error, got %v", err)
	}

	// 11. validateAggregationCursor missing port
	cursor.Endpoint = AggregationEndpointTopPorts
	cursor.Port = nil
	err = validateAggregationCursor(query, AggregationEndpointTopPorts)
	if err == nil || !strings.Contains(err.Error(), "missing port") {
		t.Errorf("expected missing port error, got %v", err)
	}

	// 12. validateAggregationCursor missing protocol key
	cursor.Endpoint = AggregationEndpointProtocols
	cursor.ProtocolNumber = nil
	err = validateAggregationCursor(query, AggregationEndpointProtocols)
	if err == nil || !strings.Contains(err.Error(), "missing protocol key") {
		t.Errorf("expected missing protocol key error, got %v", err)
	}

	// 13. validateAggregationCursor invalid endpoint
	cursor.Endpoint = AggregationEndpoint("invalid")
	err = validateAggregationCursor(query, AggregationEndpoint("invalid"))
	if err == nil || !strings.Contains(err.Error(), "invalid aggregation endpoint") {
		t.Errorf("expected invalid aggregation endpoint error, got %v", err)
	}
}
