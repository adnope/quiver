package main

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMainExitsWhenConfigPathMissing(t *testing.T) {
	if os.Getenv("QUIVER_TEST_MAIN_MISSING_CONFIG") == "1" {
		_ = os.Unsetenv("QUIVER_CONFIG")
		main()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestMainExitsWhenConfigPathMissing") //nolint:gosec // test intentionally re-execs the current test binary.
	cmd.Env = append(os.Environ(), "QUIVER_TEST_MAIN_MISSING_CONFIG=1", "QUIVER_CONFIG=")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("main() exited successfully, want failure; output=%s", output)
	}
	if ctx.Err() != nil {
		t.Fatalf("main() test subprocess timed out: %v; output=%s", ctx.Err(), output)
	}
	if !strings.Contains(string(output), "missing config path") {
		t.Fatalf("output = %s, want missing config path", output)
	}
}

func TestMainExitsWhenConfigCannotBeLoaded(t *testing.T) {
	if os.Getenv("QUIVER_TEST_MAIN_BAD_CONFIG") == "1" {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		os.Args = []string{os.Args[0], "-config", os.Getenv("QUIVER_TEST_CONFIG_PATH")}
		main()
		return
	}

	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("server: ["), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	output := runQuiverMainSubprocess(t, "TestMainExitsWhenConfigCannotBeLoaded", "QUIVER_TEST_MAIN_BAD_CONFIG=1", "QUIVER_TEST_CONFIG_PATH="+path)
	if !strings.Contains(output, "load config failed") {
		t.Fatalf("output = %s, want load config failed", output)
	}
}

func TestMainExitsWhenDatabaseCannotBeOpened(t *testing.T) {
	if os.Getenv("QUIVER_TEST_MAIN_DB_FAIL") == "1" {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		os.Args = []string{os.Args[0], "-config", os.Getenv("QUIVER_TEST_CONFIG_PATH")}
		main()
		return
	}

	path := filepath.Join(t.TempDir(), "quiver.yaml")
	config := strings.Join([]string{
		"server:",
		`  http_addr: "127.0.0.1:0"`,
		"kafka:",
		`  brokers: ["127.0.0.1:9092"]`,
		"  topics:",
		`    raw: "flow.raw"`,
		`    dead_letter: "flow.dead_letter"`,
		"database:",
		`  dsn: "postgres://quiver@127.0.0.1:1/quiver?sslmode=disable"`,
		`  schema: "quiver"`,
		`  max_open_conns: 1`,
		`  max_idle_conns: 1`,
		"api:",
		"  cursor:",
		`    hmac_secret_env: "CURSOR_SECRET"`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	output := runQuiverMainSubprocess(
		t,
		"TestMainExitsWhenDatabaseCannotBeOpened",
		"QUIVER_TEST_MAIN_DB_FAIL=1",
		"QUIVER_TEST_CONFIG_PATH="+path,
		"CURSOR_SECRET=0123456789abcdef0123456789abcdef",
	)
	if !strings.Contains(output, "open database failed") {
		t.Fatalf("output = %s, want open database failed", output)
	}
}

func runQuiverMainSubprocess(t *testing.T, testName string, env ...string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+testName+"$") //nolint:gosec // test intentionally re-execs the current test binary.
	cmd.Env = append(os.Environ(), env...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("main() exited successfully, want failure; output=%s", output)
	}
	if ctx.Err() != nil {
		t.Fatalf("main() test subprocess timed out: %v; output=%s", ctx.Err(), output)
	}
	return string(output)
}
