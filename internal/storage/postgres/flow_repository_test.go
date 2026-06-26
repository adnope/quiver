package postgres

import (
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
