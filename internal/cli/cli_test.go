package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"-h"}} {
		code, out, _ := run(t, args...)
		if code != 0 || !strings.Contains(out, "Usage:") {
			t.Errorf("%v: code %d, out %q", args, code, out)
		}
	}
}

func TestInitAndEmptySources(t *testing.T) {
	db := filepath.Join(t.TempDir(), "x", "drivecat.db")

	code, out, errOut := run(t, "--db", db, "init")
	if code != 0 || !strings.Contains(out, "schema version 1") {
		t.Fatalf("init: code %d, out %q, err %q", code, out, errOut)
	}
	if _, err := os.Stat(db); err != nil {
		t.Fatalf("database not created: %v", err)
	}

	code, out, _ = run(t, "--db", db, "sources")
	if code != 0 || !strings.Contains(out, "No sources yet") {
		t.Fatalf("sources: code %d, out %q", code, out)
	}
}

func TestDBFromEnvironment(t *testing.T) {
	db := filepath.Join(t.TempDir(), "env.db")
	t.Setenv("DRIVECAT_DB", db)
	if code, _, errOut := run(t, "init"); code != 0 {
		t.Fatalf("init: %s", errOut)
	}
	if _, err := os.Stat(db); err != nil {
		t.Fatalf("DRIVECAT_DB ignored: %v", err)
	}
}

func TestUsageErrors(t *testing.T) {
	db := filepath.Join(t.TempDir(), "drivecat.db")
	for _, args := range [][]string{
		{"--db", db, "frobnicate"},
		{"--db", db, "init", "extra"},
		{"--nope"},
	} {
		if code, _, errOut := run(t, args...); code != 2 || !strings.Contains(errOut, "Usage:") {
			t.Errorf("%v: code %d, stderr %q", args, code, errOut)
		}
	}
}

func TestNotImplementedYet(t *testing.T) {
	db := filepath.Join(t.TempDir(), "drivecat.db")
	if code, _, errOut := run(t, "--db", db, "scan", "E:\\"); code != 1 || !strings.Contains(errOut, "not implemented") {
		t.Errorf("scan: code %d, stderr %q", code, errOut)
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[int64]string{
		0:                 "0 B",
		1023:              "1023 B",
		1024:              "1.0 KiB",
		1536:              "1.5 KiB",
		5 << 30:           "5.0 GiB",
		4_000_000_000_000: "3.6 TiB",
	}
	for n, want := range cases {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
