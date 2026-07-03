package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type tcpCapture struct {
	lines []string
	err   error
}

func TestRunValidatesInputs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  string
		fn   func() error
	}{
		{name: "target", err: "target", fn: func() error { return run("", "key", 1, false, time.Second) }},
		{name: "key", err: "api key", fn: func() error { return run("127.0.0.1:1", "", 1, false, time.Second) }},
		{name: "count", err: "count", fn: func() error { return run("127.0.0.1:1", "key", 0, false, time.Second) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("error = %v, want containing %q", err, tc.err)
			}
		})
	}
}

func TestRunSendsRecords(t *testing.T) {
	t.Parallel()

	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close listener: %v", err)
		}
	}()

	captures := make(chan tcpCapture, 1)
	go captureLines(listener, 3, captures)

	if err := run(listener.Addr().String(), " secret ", 2, false, time.Second); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	capture := <-captures
	if capture.err != nil {
		t.Fatalf("capture lines: %v", capture.err)
	}
	got := capture.lines
	if len(got) != 3 {
		t.Fatalf("lines = %v", got)
	}
	if got[0] != "X-API-Key: secret" {
		t.Fatalf("auth preface = %q", got[0])
	}
	var rec zeekRecord
	if err := json.Unmarshal([]byte(got[1]), &rec); err != nil {
		t.Fatalf("unmarshal line: %v", err)
	}
	if rec.UID == "" || rec.OrigP != 50000 || rec.RespP != 443 {
		t.Fatalf("record = %+v", rec)
	}
}

func TestRunSendsMalformedLine(t *testing.T) {
	t.Parallel()

	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close listener: %v", err)
		}
	}()

	captures := make(chan tcpCapture, 1)
	go captureLines(listener, 2, captures)

	if err := run(listener.Addr().String(), "key", 1, true, time.Second); err != nil {
		t.Fatalf("run(malformed) error = %v", err)
	}
	capture := <-captures
	if capture.err != nil {
		t.Fatalf("capture lines: %v", capture.err)
	}
	got := capture.lines
	if len(got) != 2 || got[1] != "{bad-json" {
		t.Fatalf("lines = %v", got)
	}
}

func TestNewRecordAndUID(t *testing.T) {
	t.Parallel()

	rec := newRecord(4)
	if rec.UID == "" || !strings.HasPrefix(rec.UID, "C") || rec.OrigP != 50004 {
		t.Fatalf("record = %+v", rec)
	}
	if uid := randomUID(); !strings.HasPrefix(uid, "C") || len(uid) < 2 {
		t.Fatalf("uid = %q", uid)
	}
}

func captureLines(listener net.Listener, want int, captures chan<- tcpCapture) {
	conn, err := listener.Accept()
	if err != nil {
		captures <- tcpCapture{err: err}
		return
	}
	defer func() {
		_ = conn.Close()
	}()

	scanner := bufio.NewScanner(conn)
	got := make([]string, 0, want)
	for scanner.Scan() {
		got = append(got, scanner.Text())
		if len(got) == want {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		captures <- tcpCapture{err: err}
		return
	}
	captures <- tcpCapture{lines: got}
}
