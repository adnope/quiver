module github.com/adnope/quiver

go 1.26

require gopkg.in/yaml.v3 v3.0.1

require (
	github.com/golang-migrate/migrate/v4 v4.19.1
	github.com/jackc/pgx/v5 v5.10.0
	github.com/twmb/franz-go v1.21.3
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.13.1 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/text v0.31.0 // indirect
)

tool google.golang.org/protobuf/cmd/protoc-gen-go
