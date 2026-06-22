package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adnope/quiver/internal/domain"
	_ "github.com/jackc/pgx/v5/stdlib"
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

	collectorIDs = []string{
		"rest-ingest-main", "zeek-sensor-eth0", "netflow-v5-gateway-router",
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

var sqlCache = make(map[int]string)
var sqlCacheMu sync.RWMutex

func buildBatchInsert(batchSize int) string {
	var buf bytes.Buffer
	buf.WriteString("INSERT INTO quiver.flow_records (id, schema_version, idempotency_key, raw_event_id, source_type, collector_id, source_host, source_ip, ingested_at, normalized_at, event_start_time, event_end_time, duration_ms, src_ip, dst_ip, src_port, dst_port, ip_version, transport_protocol, protocol_number, bytes, packets, tcp_flags, flow_state, direction, input_interface, output_interface, next_hop_ip, application_protocol, sampling_rate, normalization_status, normalization_error, attributes) VALUES ")
	paramIdx := 1
	for i := 0; i < batchSize; i++ {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString("(")
		for j := 0; j < 33; j++ {
			if j > 0 {
				buf.WriteString(",")
			}
			buf.WriteString(fmt.Sprintf("$%d", paramIdx))
			paramIdx++
		}
		buf.WriteString(")")
	}
	return buf.String()
}

func getInsertSQL(batchSize int) string {
	sqlCacheMu.RLock()
	sql, ok := sqlCache[batchSize]
	sqlCacheMu.RUnlock()
	if ok {
		return sql
	}
	sql = buildBatchInsert(batchSize)
	sqlCacheMu.Lock()
	sqlCache[batchSize] = sql
	sqlCacheMu.Unlock()
	return sql
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
	totalRecords := flag.Int("records", 1000000, "Total number of records to seed (default 1M for safety, can set to 10M)")
	daysRange := flag.Int("days", 30, "Number of days to span records over")
	concurrency := flag.Int("concurrency", 8, "Number of concurrent DB insert workers")
	flag.Parse()

	dbDSN := *dsn
	if dbDSN == "" {
		dbDSN = os.Getenv("QUIVER_DATABASE_DSN_HOST")
	}
	if dbDSN == "" {
		dbDSN = "postgres://postgres:postgres@localhost:5432/quiver?sslmode=disable"
	}

	fmt.Printf("Connecting to database: %s\n", dbDSN)
	db, err := sql.Open("pgx", dbDSN)
	if err != nil {
		fmt.Printf("Connection error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	db.SetMaxOpenConns(*concurrency + 2)

	if err := db.Ping(); err != nil {
		fmt.Printf("Database ping failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Database connection verified.")
	fmt.Printf("Seeding %d records distributed over %d days using %d concurrent workers...\n", *totalRecords, *daysRange, *concurrency)

	startTime := time.Now()
	var insertedCount int64

	// Distribute records across days using a normal distribution
	dayRecords := distributeNormal(rand.New(rand.NewSource(time.Now().UnixNano())), *totalRecords, *daysRange)

	// We seed day-by-day to keep TimescaleDB hypertable inserts localized per partition chunk
	for day := 0; day < *daysRange; day++ {
		dayStart := time.Now().AddDate(0, 0, -(*daysRange - day))
		recordsToInsert := dayRecords[day]
		fmt.Printf("Seeding day %d/%d (%s) - %d records...\n", day+1, *daysRange, dayStart.Format("2006-01-02"), recordsToInsert)

		jobs := make(chan []any, 100)
		var wg sync.WaitGroup

		// Start workers
		for w := 0; w < *concurrency; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var localBatch [][]any
				batchLimit := 1000

				flushBatch := func() {
					if len(localBatch) == 0 {
						return
					}
					sqlStr := getInsertSQL(len(localBatch))
					flatArgs := make([]any, 0, len(localBatch)*33)
					for _, row := range localBatch {
						flatArgs = append(flatArgs, row...)
					}

					for attempt := 1; attempt <= 3; attempt++ {
						_, err := db.Exec(sqlStr, flatArgs...)
						if err == nil {
							atomic.AddInt64(&insertedCount, int64(len(localBatch)))
							break
						}
						if attempt == 3 {
							fmt.Printf("Database write failed after 3 attempts: %v\n", err)
						} else {
							time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
						}
					}
					localBatch = localBatch[:0]
				}

				for row := range jobs {
					localBatch = append(localBatch, row)
					if len(localBatch) >= batchLimit {
						flushBatch()
					}
				}
				flushBatch()
			}()
		}

		// Generate rows for the day
		r := rand.New(rand.NewSource(int64(day)))
		for i := 0; i < recordsToInsert; i++ {
			// Random time within this specific day
			offsetSeconds := r.Intn(24 * 3600)
			eventStart := dayStart.Add(time.Duration(offsetSeconds) * time.Second)

			// Realistic traffic template
			tpl := templates[r.Intn(len(templates))]

			// Choose IP and ports
			var srcIP, dstIP string
			var srcPortVal, dstPortVal uint16
			var direction string

			if tpl.direction == "internal" {
				srcIP = internalIPs[r.Intn(len(internalIPs))]
				dstIP = internalIPs[r.Intn(len(internalIPs))]
				for srcIP == dstIP {
					dstIP = internalIPs[r.Intn(len(internalIPs))]
				}
				srcPortVal = uint16(49152 + r.Intn(16384))
				dstPortVal = uint16(tpl.port)
				direction = "internal"
			} else {
				// Outbound or inbound
				if r.Float32() < 0.85 {
					srcIP = internalIPs[r.Intn(len(internalIPs))]
					dstIP = publicIPs[r.Intn(len(publicIPs))]
					srcPortVal = uint16(49152 + r.Intn(16384))
					dstPortVal = uint16(tpl.port)
					direction = "outbound"
				} else {
					srcIP = publicIPs[r.Intn(len(publicIPs))]
					dstIP = internalIPs[r.Intn(len(internalIPs))]
					srcPortVal = uint16(tpl.port)
					dstPortVal = uint16(49152 + r.Intn(16384))
					direction = "inbound"
				}
			}

			// Packets and bytes
			packetsVal := uint64(tpl.avgPackets + r.Int63n(tpl.avgPackets/2+1))
			if packetsVal == 0 {
				packetsVal = 1
			}
			bytesVal := uint64(packetsVal * uint64(tpl.avgBytes+r.Int63n(100)))

			// Sources mapping
			sourceIndex := r.Intn(3)
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
				sourceHost = sourceHosts[r.Intn(len(sourceHosts))]
				attributesJson = fmt.Sprintf(`{"conn_state": "SF", "uid": "C%x", "service": "%s"}`, r.Uint64(), tpl.app)
			default:
				sourceType = "netflow_v5"
				collectorID = "netflow-v5-gateway-router"
				sourceHost = "router-edge-01"
				sip := "172.20.0.1"
				sourceIPStr = &sip
				attributesJson = `{"engine_type": 1, "engine_id": 2, "snmp_input": 10, "snmp_output": 11}`
			}

			// Generate aligned UUIDv7
			id, _ := domain.NewUUIDv7(eventStart)
			rawEventID, _ := domain.NewUUIDv7(eventStart.Add(-10 * time.Millisecond))

			// Duration
			durationMS := int64(10 + r.Intn(2000))
			eventEnd := eventStart.Add(time.Duration(durationMS) * time.Millisecond)

			// Idempotency key
			idKey := buildIdempotencyKeyLocal(eventStart, srcIP, dstIP, &srcPortVal, &dstPortVal, &bytesVal, &packetsVal)

			tcpFlags := 0
			if tpl.protocol == "tcp" {
				tcpFlags = 0x18 // PSH, ACK
			}

			// Scan fields in query order
			row := []any{
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
			}

			jobs <- row
		}

		close(jobs)
		wg.Wait()
	}

	elapsed := time.Since(startTime)
	rate := float64(insertedCount) / elapsed.Seconds()
	fmt.Printf("\nSeeding complete! Successfully inserted %d flow records directly to database.\n", insertedCount)
	fmt.Printf("Elapsed time: %v. Insertion rate: %.2f records/second.\n", elapsed, rate)
}

// distributeNormal returns a slice of length `days` whose values sum to `total`,
// drawn from a normal distribution centered on total/days with stddev = 40% of the mean.
func distributeNormal(r *rand.Rand, total, days int) []int {
	if days <= 0 {
		return nil
	}
	mean := float64(total) / float64(days)
	stddev := mean * 0.4

	counts := make([]int, days)
	var sum int
	for i := 0; i < days-1; i++ {
		v := int(r.NormFloat64()*stddev + mean)
		if v < 1 {
			v = 1
		}
		counts[i] = v
		sum += v
	}
	// Last day absorbs the remainder to guarantee exact total
	counts[days-1] = total - sum
	if counts[days-1] < 1 {
		counts[days-1] = 1
	}
	return counts
}
