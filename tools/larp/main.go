//nolint:gosec,modernize // This simulation seeder intentionally uses non-cryptographic randomness, local defaults, and SQL commands.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/adnope/quiver/internal/domain"
)

var (
	internalIPs = []string{
		"192.168.1.10", "192.168.1.20", "192.168.1.50", "192.168.1.100",
		"10.0.0.5", "10.0.0.10", "10.0.0.100", "10.1.10.5",
		"172.16.5.12", "172.16.5.15", "172.20.10.2",
	}

	publicIPs = []string{
		"8.8.8.8", "1.1.1.1", "142.250.190.46", "52.216.102.163",
		"13.107.42.14", "104.244.42.1", "157.240.22.35", "185.199.108.153",
		"20.42.65.159", "23.212.44.10", "172.217.16.142",
	}

	sourceHosts = []string{
		"web-server-01", "web-server-02", "db-primary-01", "db-replica-01",
		"app-gateway-01", "app-gateway-02", "mail-server-01", "redis-cache-01",
		"developer-workstation-mac", "marketing-pc-01", "finance-pc-02",
	}

	durationHistogramUpperBounds = []float64{
		1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000,
	}
)

type flowTemplate struct {
	protocol       string
	protocolNumber int
	port           int
	app            string
	avgPackets     int64
	avgBytes       int64
	direction      string
}

var templates = []flowTemplate{
	{"tcp", 6, 443, "https", 150, 1200, "outbound"},
	{"tcp", 6, 80, "http", 20, 1000, "outbound"},
	{"tcp", 6, 22, "ssh", 500, 1300, "internal"},
	{"tcp", 6, 3306, "mysql", 1000, 800, "internal"},
	{"tcp", 6, 5432, "postgres", 2000, 850, "internal"},
	{"tcp", 6, 6379, "redis", 50, 200, "internal"},
	{"udp", 17, 53, "dns", 2, 75, "outbound"},
	{"udp", 17, 123, "ntp", 2, 76, "outbound"},
	{"udp", 17, 443, "quic", 200, 1250, "outbound"},
	{"icmp", 1, 0, "ping", 4, 64, "internal"},
}

func buildIdempotencyKeyLocal(startTime time.Time, srcIP, dstIP string, srcPort, dstPort *uint16, bytesVal, packetsVal *uint64) string {
	parts := []string{
		"flow.v1",
		"rest_json",
		"rest-ingest-main",
		"demo-host-0",
		"rest-external-1",
		startTime.UTC().Format(time.RFC3339Nano),
		"", // EventEndTime
		srcIP,
		dstIP,
		formatOptionalUint16(srcPort),
		formatOptionalUint16(dstPort),
		"6", // ProtocolNumber
		formatOptionalUint64(bytesVal),
		formatOptionalUint64(packetsVal),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func formatOptionalUint16(v *uint16) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%d", *v)
}

func formatOptionalUint64(v *uint64) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%d", *v)
}

func main() {
	dsn := flag.String("dsn", "", "PostgreSQL database DSN")
	totalRecords := flag.Int("records", 10000000, "Total number of records to seed (default 10M)")
	daysRange := flag.Int("days", 30, "Number of days to simulate load over")
	flag.Parse()

	dbDSN := *dsn
	if dbDSN == "" {
		dbDSN = os.Getenv("QUIVER_DATABASE_DSN_HOST")
	}
	if dbDSN == "" {
		dbDSN = "postgres://postgres:postgres@localhost:5432/quiver?sslmode=disable"
	}

	ctx := context.Background()
	fmt.Printf("Connecting to database: %s\n", dbDSN)
	conn, err := pgx.Connect(ctx, dbDSN)
	if err != nil {
		fmt.Printf("Connection error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close(ctx) }()
	fmt.Println("Database connection verified.")

	// 1. Calculate weights for each hour to distribute load realistically
	totalHours := *daysRange * 24
	hourlyWeights := make([]float64, totalHours)
	var totalWeight float64

	now := time.Now().UTC()
	startSimTime := now.Add(-time.Duration(*daysRange) * 24 * time.Hour)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for h := 0; h < totalHours; h++ {
		hourStart := startSimTime.Add(time.Duration(h) * time.Hour)

		// Weekend factor (Saturdays and Sundays have 20% of normal traffic)
		dayFactor := 1.0
		if hourStart.Weekday() == time.Saturday || hourStart.Weekday() == time.Sunday {
			dayFactor = 0.2
		}

		// Diurnal cycle peaking at 14:00 (2 PM) and troughing at 03:00 (3 AM)
		hourOfDay := hourStart.Hour()
		hourFactor := 0.5 + 0.45*math.Sin(float64(hourOfDay-8)*math.Pi/12.0)

		// Occasional random daily spikes
		spikeFactor := 1.0
		if rng.Float64() < 0.05 { // 5% chance of a bursty hour
			spikeFactor = 2.5
		}

		weight := dayFactor * hourFactor * spikeFactor
		hourlyWeights[h] = weight
		totalWeight += weight
	}

	fmt.Printf("Seeding ~%d records distributed over %d days (%d hours)...\n", *totalRecords, *daysRange, totalHours)

	var totalFlowsInserted int64
	var totalAggsInserted int64
	var totalHistInserted int64

	// 2. Loop hour-by-hour and seed records
	for h := 0; h < totalHours; h++ {
		hourStart := startSimTime.Add(time.Duration(h) * time.Hour)
		targetFlows := int(float64(*totalRecords) * hourlyWeights[h] / totalWeight)
		if targetFlows <= 0 {
			targetFlows = 1 // Ensure at least some activity exists
		}

		// Prepare hourly buffers for CopyFrom
		var flowRows [][]any
		var aggRows [][]any
		var histRows [][]any

		// We have 720 five-second buckets in an hour (3600 / 5)
		numBuckets := 720
		flowsPerBucketBase := targetFlows / numBuckets

		for b := 0; b < numBuckets; b++ {
			bucketStart := hourStart.Add(time.Duration(b) * 5 * time.Second)

			// Add a bit of jitter to flow count per bucket
			flowsCount := flowsPerBucketBase
			if flowsPerBucketBase > 2 {
				flowsCount = flowsPerBucketBase - flowsPerBucketBase/4 + rng.Intn(flowsPerBucketBase/2)
			} else {
				if rng.Float32() < 0.3 {
					flowsCount = rng.Intn(3)
				}
			}

			// Occasional high load spikes within the hour (e.g. testing peak tooltips)
			if rng.Float64() < 0.005 {
				flowsCount = flowsCount * 10 // 10x burst
			}

			// In-memory counters for system_metric_aggregates
			sourceCounts := map[string]int{
				"rest_json":      0,
				"zeek_conn_json": 0,
				"netflow_v5":     0,
				"netflow_v9":     0,
			}

			var storageDurations []float64

			// Simulate and generate each flow record in the 5s bucket
			for range flowsCount {
				offsetSec := rng.Float64() * 5.0
				eventStart := bucketStart.Add(time.Duration(offsetSec * float64(time.Second)))

				tpl := templates[rng.Intn(len(templates))]

				var srcIP, dstIP string
				var srcPortVal, dstPortVal uint16
				var direction string

				if tpl.direction == "internal" {
					srcIP = internalIPs[rng.Intn(len(internalIPs))]
					dstIP = internalIPs[rng.Intn(len(internalIPs))]
					for srcIP == dstIP {
						dstIP = internalIPs[rng.Intn(len(internalIPs))]
					}
					srcPortVal = uint16(49152 + rng.Intn(16384))
					dstPortVal = uint16(tpl.port)
					direction = "internal"
				} else {
					if rng.Float32() < 0.85 {
						srcIP = internalIPs[rng.Intn(len(internalIPs))]
						dstIP = publicIPs[rng.Intn(len(publicIPs))]
						srcPortVal = uint16(49152 + rng.Intn(16384))
						dstPortVal = uint16(tpl.port)
						direction = "outbound"
					} else {
						srcIP = publicIPs[rng.Intn(len(publicIPs))]
						dstIP = internalIPs[rng.Intn(len(internalIPs))]
						srcPortVal = uint16(tpl.port)
						dstPortVal = uint16(49152 + rng.Intn(16384))
						direction = "inbound"
					}
				}

				packetsVal := uint64(tpl.avgPackets + rng.Int63n(tpl.avgPackets/2+1))
				if packetsVal == 0 {
					packetsVal = 1
				}
				bytesVal := packetsVal * uint64(tpl.avgBytes+rng.Int63n(100))

				// Pick source types and update metrics registry tracker
				sourceIndex := rng.Intn(4)
				var sourceType, collectorID, sourceHost string
				var sourceIPStr *string
				var attributesJson string

				switch sourceIndex {
				case 0:
					sourceType = "rest_json"
					collectorID = "rest-ingest-main"
					sourceHost = "rest-gateway-01"
					attributesJson = `{"ingest_agent": "restgen", "api_version": "v1"}`
				case 1:
					sourceType = "zeek_conn_json"
					collectorID = "zeek-sensor-eth0"
					sourceHost = sourceHosts[rng.Intn(len(sourceHosts))]
					attributesJson = fmt.Sprintf(`{"conn_state": "SF", "uid": "C%x", "service": "%s"}`, rng.Uint64(), tpl.app)
				case 2:
					sourceType = "netflow_v5"
					collectorID = "netflow-v5-gateway-router"
					sourceHost = "router-edge-01"
					sip := "172.20.0.1"
					sourceIPStr = &sip
					attributesJson = `{"engine_type": 1, "engine_id": 2, "snmp_input": 10, "snmp_output": 11}`
				default:
					sourceType = "netflow_v9"
					collectorID = "netflow-v9-main"
					sourceHost = "router-edge-02"
					sip := "172.20.0.2"
					sourceIPStr = &sip
					attributesJson = fmt.Sprintf(
						`{"DIRECTION": "0", "FIRST_SWITCHED": "5000", "INPUT_SNMP": "2", "IN_BYTES": "%d", "IN_PKTS": "%d", "IPV4_DST_ADDR": "%s", "IPV4_SRC_ADDR": "%s", "L4_DST_PORT": "%d", "L4_SRC_PORT": "%d", "LAST_SWITCHED": "5100", "OUTPUT_SNMP": "3", "PROTOCOL": "%d"}`,
						bytesVal, packetsVal, dstIP, srcIP, dstPortVal, srcPortVal, tpl.protocolNumber,
					)
				}

				sourceCounts[sourceType]++

				id, _ := domain.NewUUIDv7(eventStart)
				rawEventID, _ := domain.NewUUIDv7(eventStart.Add(-10 * time.Millisecond))

				durationMS := int64(10 + rng.Intn(2000))
				eventEnd := eventStart.Add(time.Duration(durationMS) * time.Millisecond)

				idKey := buildIdempotencyKeyLocal(eventStart, srcIP, dstIP, &srcPortVal, &dstPortVal, &bytesVal, &packetsVal)

				tcpFlags := 0
				if tpl.protocol == "tcp" {
					tcpFlags = 0x18
				}

				// Simulate storage insertion duration (DB write latency)
				// Correlate latency with flow volume (higher volume = slightly higher latency)
				loadFactor := float64(flowsCount) / 100.0
				minLat := 0.5 + rng.Float64()*1.0
				avgLat := 2.0 + 8.0*math.Log1p(loadFactor) + rng.Float64()*3.0
				latVal := minLat + rng.ExpFloat64()*(avgLat-minLat)
				storageDurations = append(storageDurations, latVal)

				flowRows = append(flowRows, []any{
					id,                              // id
					"flow.v1",                       // schema_version
					idKey,                           // idempotency_key
					rawEventID,                      // raw_event_id
					sourceType,                      // source_type
					collectorID,                     // collector_id
					sourceHost,                      // source_host
					sourceIPStr,                     // source_ip
					eventStart.Add(2 * time.Second), // ingested_at
					eventStart.Add(3 * time.Second), // normalized_at
					eventStart,                      // event_start_time
					eventEnd,                        // event_end_time
					durationMS,                      // duration_ms
					srcIP,                           // src_ip
					dstIP,                           // dst_ip
					int(srcPortVal),                 // src_port
					int(dstPortVal),                 // dst_port
					4,                               // ip_version
					tpl.protocol,                    // transport_protocol
					tpl.protocolNumber,              // protocol_number
					int64(bytesVal),                 // bytes
					int64(packetsVal),               // packets
					tcpFlags,                        // tcp_flags
					"ESTABLISHED",                   // flow_state
					direction,                       // direction
					10,                              // input_interface
					11,                              // output_interface
					"172.20.0.1",                    // next_hop_ip
					tpl.app,                         // application_protocol
					1,                               // sampling_rate
					"ok",                            // normalization_status
					nil,                             // normalization_error
					attributesJson,                  // attributes
				})
			}

			// Generate system metrics for this 5-second bucket
			// Metric: flow_records_normalized_total
			for srcType, count := range sourceCounts {
				if count > 0 {
					labelsBytes, _ := json.Marshal(map[string]string{"source_type": srcType})
					aggRows = append(aggRows, []any{
						bucketStart,                     // bucket_start
						5,                               // bucket_width_seconds
						"flow_records_normalized_total", // metric_name
						labelsBytes,                     // labels
						"counter",                       // metric_kind
						int64(1),                        // sample_count
						int64(1),                        // count
						nil,                             // sum
						nil,                             // avg
						nil,                             // min
						nil,                             // max
						nil,                             // p90
						nil,                             // p95
						nil,                             // p99
						nil,                             // first
						nil,                             // last
						float64(count),                  // delta
					})
				}
			}

			// Metric: flow_records_stored_total
			if flowsCount > 0 {
				labelsBytes, _ := json.Marshal(map[string]string{})
				aggRows = append(aggRows, []any{
					bucketStart,                 // bucket_start
					5,                           // bucket_width_seconds
					"flow_records_stored_total", // metric_name
					labelsBytes,                 // labels
					"counter",                   // metric_kind
					int64(1),                    // sample_count
					int64(1),                    // count
					nil,                         // sum
					nil,                         // avg
					nil,                         // min
					nil,                         // max
					nil,                         // p90
					nil,                         // p95
					nil,                         // p99
					nil,                         // first
					nil,                         // last
					float64(flowsCount),         // delta
				})
			}

			// Metric: storage_insert_duration (duration latency statistics)
			if len(storageDurations) > 0 {
				sort.Float64s(storageDurations)
				var sum float64
				for _, d := range storageDurations {
					sum += d
				}
				count := len(storageDurations)
				minVal := storageDurations[0]
				maxVal := storageDurations[count-1]
				avgVal := sum / float64(count)
				p90Val := storageDurations[int(float64(count)*0.90)]
				p95Val := storageDurations[int(float64(count)*0.95)]
				p99Val := storageDurations[int(float64(count)*0.99)]
				firstVal := storageDurations[0]
				lastVal := storageDurations[count-1]

				labelsBytes, _ := json.Marshal(map[string]string{"status": "ok"})
				aggRows = append(aggRows, []any{
					bucketStart,               // bucket_start
					5,                         // bucket_width_seconds
					"storage_insert_duration", // metric_name
					labelsBytes,               // labels
					"duration",                // metric_kind
					int64(count),              // sample_count
					int64(count),              // count
					sum,                       // sum
					avgVal,                    // avg
					minVal,                    // min
					maxVal,                    // max
					p90Val,                    // p90
					p95Val,                    // p95
					p99Val,                    // p99
					firstVal,                  // first
					lastVal,                   // last
					nil,                       // delta
				})

				// Populate duration histogram buckets
				histCounts := make([]int64, len(durationHistogramUpperBounds)+1)
				for _, d := range storageDurations {
					placed := false
					for idx, ub := range durationHistogramUpperBounds {
						if d <= ub {
							histCounts[idx]++
							placed = true
							break
						}
					}
					if !placed {
						histCounts[len(durationHistogramUpperBounds)]++
					}
				}

				for idx, cnt := range histCounts {
					if cnt > 0 {
						var ubVal *float64
						if idx < len(durationHistogramUpperBounds) {
							ubVal = &durationHistogramUpperBounds[idx]
						}
						histRows = append(histRows, []any{
							bucketStart,               // bucket_start
							5,                         // bucket_width_seconds
							"storage_insert_duration", // metric_name
							labelsBytes,               // labels
							idx,                       // bucket_index
							ubVal,                     // bucket_upper_bound
							cnt,                       // count
						})
					}
				}
			}

			// Metric: kafka_consumer_lag (gauge, correlated with high flow volume spikes)
			lagVal := 0
			if flowsCount > 120 {
				lagVal = (flowsCount - 120) * (2 + rng.Intn(4))
			}
			labelsBytes, _ := json.Marshal(map[string]string{"topic": "flow.raw", "partition": "0"})
			aggRows = append(aggRows, []any{
				bucketStart,          // bucket_start
				5,                    // bucket_width_seconds
				"kafka_consumer_lag", // metric_name
				labelsBytes,          // labels
				"gauge",              // metric_kind
				int64(1),             // sample_count
				int64(1),             // count
				float64(lagVal),      // sum
				float64(lagVal),      // avg
				float64(lagVal),      // min
				float64(lagVal),      // max
				nil,                  // p90
				nil,                  // p95
				nil,                  // p99
				float64(lagVal),      // first
				float64(lagVal),      // last
				nil,                  // delta
			})
		}

		// 3. Write flow records to database using PGX CopyFrom
		if len(flowRows) > 0 {
			copyCols := []string{
				"id", "schema_version", "idempotency_key", "raw_event_id", "source_type",
				"collector_id", "source_host", "source_ip", "ingested_at", "normalized_at",
				"event_start_time", "event_end_time", "duration_ms", "src_ip", "dst_ip",
				"src_port", "dst_port", "ip_version", "transport_protocol", "protocol_number",
				"bytes", "packets", "tcp_flags", "flow_state", "direction",
				"input_interface", "output_interface", "next_hop_ip", "application_protocol",
				"sampling_rate", "normalization_status", "normalization_error", "attributes",
			}
			n, err := conn.CopyFrom(
				ctx,
				pgx.Identifier{"quiver", "flow_records"},
				copyCols,
				pgx.CopyFromRows(flowRows),
			)
			if err != nil {
				fmt.Printf("\nFailed to copy flows for hour %d/%d: %v\n", h+1, totalHours, err)
				os.Exit(1)
			}
			totalFlowsInserted += n
		}

		// 4. Write system_metric_aggregates using CopyFrom
		if len(aggRows) > 0 {
			copyCols := []string{
				"bucket_start", "bucket_width_seconds", "metric_name", "labels", "metric_kind",
				"sample_count", "count", "sum", "avg", "min", "max",
				"p90", "p95", "p99", "first", "last", "delta",
			}
			n, err := conn.CopyFrom(
				ctx,
				pgx.Identifier{"quiver", "system_metric_aggregates"},
				copyCols,
				pgx.CopyFromRows(aggRows),
			)
			if err != nil {
				fmt.Printf("\nFailed to copy aggregates for hour %d/%d: %v\n", h+1, totalHours, err)
				os.Exit(1)
			}
			totalAggsInserted += n
		}

		// 5. Write system_metric_histogram_buckets using CopyFrom
		if len(histRows) > 0 {
			copyCols := []string{
				"bucket_start", "bucket_width_seconds", "metric_name", "labels",
				"bucket_index", "bucket_upper_bound", "count",
			}
			n, err := conn.CopyFrom(
				ctx,
				pgx.Identifier{"quiver", "system_metric_histogram_buckets"},
				copyCols,
				pgx.CopyFromRows(histRows),
			)
			if err != nil {
				fmt.Printf("\nFailed to copy histograms for hour %d/%d: %v\n", h+1, totalHours, err)
				os.Exit(1)
			}
			totalHistInserted += n
		}

		// Print progress
		progress := float64(h+1) / float64(totalHours) * 100
		fmt.Printf("\rProgress: %.1f%% (%d/%d hours) - Flow records: %d", progress, h+1, totalHours, totalFlowsInserted)
	}
	fmt.Println()

	// 6. Refresh continuous aggregates for Analytics tabs
	fmt.Println("Refreshing TimescaleDB continuous aggregates (this can take a few seconds)...")
	_, err = conn.Exec(ctx, "CALL refresh_continuous_aggregate('quiver.flow_hourly_talkers', NULL, NULL)")
	if err != nil {
		fmt.Printf("Warning: failed to refresh flow_hourly_talkers: %v\n", err)
	}
	_, err = conn.Exec(ctx, "CALL refresh_continuous_aggregate('quiver.flow_hourly_ports', NULL, NULL)")
	if err != nil {
		fmt.Printf("Warning: failed to refresh flow_hourly_ports: %v\n", err)
	}

	// 7. Seed collector heartbeats to represent active shippers in frontend
	fmt.Println("Seeding active collector states...")
	collectorsToSeed := []struct {
		cid   string
		stype string
		host  string
	}{
		{"netflow-v9-main", "netflow_v9", "router-edge-02"},
		{"netflow-v5-gateway-router", "netflow_v5", "router-edge-01"},
		{"zeek-sensor-eth0", "zeek_conn_json", "app-gateway-01"},
		{"rest-ingest-main", "rest_json", "rest-gateway-01"},
	}

	for _, coll := range collectorsToSeed {
		stateKey := fmt.Sprintf("collector:%s", coll.cid)
		stateJSON, _ := json.Marshal(map[string]any{
			"status":            "healthy",
			"active_flows_rate": 25.5,
			"ingestion_errors":  0,
		})
		query := `
			INSERT INTO quiver.collector_states (state_key, collector_id, source_type, source_host, state, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (state_key) DO UPDATE SET
				state = EXCLUDED.state,
				updated_at = EXCLUDED.updated_at`
		_, err = conn.Exec(ctx, query, stateKey, coll.cid, coll.stype, coll.host, stateJSON, time.Now().UTC())
		if err != nil {
			fmt.Printf("Warning: failed to seed collector %s: %v\n", coll.cid, err)
		}
	}

	fmt.Println("\nSeeding complete!")
	fmt.Printf("- Flow records inserted: %d\n", totalFlowsInserted)
	fmt.Printf("- Performance aggregates inserted: %d\n", totalAggsInserted)
	fmt.Printf("- Duration histogram buckets inserted: %d\n", totalHistInserted)
	fmt.Println("All charts and analytics are now populated with consistent, load-correlated history.")
}
