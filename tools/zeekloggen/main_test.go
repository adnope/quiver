package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildRecords(t *testing.T) {
	t.Parallel()

	records, err := buildRecords(2, false)
	if err != nil {
		t.Fatalf("buildRecords() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want 2", len(records))
	}
	var rec ZeekRecord
	if err := json.Unmarshal(records[0], &rec); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	if rec.UID == "" || rec.OrigH == "" || rec.RespH == "" || rec.Proto == "" {
		t.Fatalf("incomplete record: %+v", rec)
	}

	if _, err := buildRecords(0, false); err == nil {
		t.Fatal("buildRecords(0) error = nil, want error")
	}

	malformed, err := buildRecords(1, true)
	if err != nil {
		t.Fatalf("buildRecords(malformed) error = %v", err)
	}
	if len(malformed) != 1 || !json.Valid(malformed[0]) {
		t.Fatalf("malformed record payload = %q", malformed)
	}
}

func TestPostRecordsValidationAndSuccess(t *testing.T) {
	t.Parallel()

	if err := postRecords("http://example.invalid", "", 1, false); err == nil || !strings.Contains(err.Error(), "api key") {
		t.Fatalf("postRecords empty key error = %v", err)
	}
	if err := postRecords("http://example.invalid", "key", 0, false); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("postRecords bad count error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ingest/zeek/conn" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "key" {
			t.Fatalf("api key = %q", r.Header.Get("X-API-Key"))
		}
		var req zeekIngestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Records) != 2 {
			t.Fatalf("records len = %d, want 2", len(req.Records))
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":2,"rejected":0}`))
	}))
	defer server.Close()

	if err := postRecords(server.URL+"/", " key ", 2, false); err != nil {
		t.Fatalf("postRecords() error = %v", err)
	}
}

func TestPostRecordsHTTPFailures(t *testing.T) {
	t.Parallel()

	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer statusServer.Close()
	if err := postRecords(statusServer.URL, "key", 1, false); err == nil || !strings.Contains(err.Error(), "unexpected status") {
		t.Fatalf("postRecords bad status error = %v", err)
	}

	jsonServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer jsonServer.Close()
	if err := postRecords(jsonServer.URL, "key", 1, false); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("postRecords bad json error = %v", err)
	}
}

func TestNewRecordAndUID(t *testing.T) {
	t.Parallel()

	rec := newRecord(3)
	if rec.UID == "" || !strings.HasPrefix(rec.UID, "C") || rec.OrigP != 49003 {
		t.Fatalf("record = %+v", rec)
	}
	if uid := randomZeekUID(); !strings.HasPrefix(uid, "C") || len(uid) < 2 {
		t.Fatalf("uid = %q", uid)
	}
}
