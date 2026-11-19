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
	db := filepath.Join(t.TempDir(), "drivecat.db")

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
	// A temp folder, never a real drive: once scan exists, this test must
	// not scan whatever happens to be E: on the machine running it.
	dir := t.TempDir()
	db := filepath.Join(dir, "drivecat.db")
	if code, _, errOut := run(t, "--db", db, "scan", dir); code != 1 || !strings.Contains(errOut, "not implemented") {
		t.Errorf("scan: code %d, stderr %q", code, errOut)
	}
}

func TestDBPathMustBeAbsolute(t *testing.T) {
	if code, _, errOut := run(t, "--db", "drivecat.db", "init"); code != 2 || !strings.Contains(errOut, "absolute") {
		t.Errorf("relative --db: code %d, stderr %q", code, errOut)
	}
	if _, err := os.Stat("drivecat.db"); err == nil {
		os.Remove("drivecat.db")
		t.Error("relative --db created a database in the current folder")
	}

	t.Setenv("DRIVECAT_DB", `x\drivecat.db`)
	if code, _, errOut := run(t, "sources"); code != 1 || !strings.Contains(errOut, "absolute") {
		t.Errorf("relative DRIVECAT_DB: code %d, stderr %q", code, errOut)
	}

	t.Setenv("DRIVECAT_DB", "")
	t.Setenv("LOCALAPPDATA", "")
	if code, _, errOut := run(t, "sources"); code != 1 || !strings.Contains(errOut, "LOCALAPPDATA") {
		t.Errorf("no LOCALAPPDATA: code %d, stderr %q", code, errOut)
	}
	// version needs no database, so it works regardless.
	if code, out, _ := run(t, "version"); code != 0 || !strings.HasPrefix(out, "drivecat ") {
		t.Errorf("version: code %d, out %q", code, out)
	}
}

func TestDefaultDBPath(t *testing.T) {
	t.Setenv("DRIVECAT_DB", "")
	t.Setenv("LOCALAPPDATA", `C:\Users\someone\AppData\Local`)
	got, isDefault, err := resolveDBPath("")
	if err != nil || !isDefault || got != `C:\Users\someone\AppData\Local\drivecat\drivecat.db` {
		t.Fatalf("resolveDBPath = %q, %v", got, err)
	}
}

func TestSourcesWithoutDatabase(t *testing.T) {
	db := filepath.Join(t.TempDir(), "drivecat.db")
	code, out, _ := run(t, "--db", db, "sources")
	if code != 0 || !strings.Contains(out, "No database") {
		t.Fatalf("code %d, out %q", code, out)
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Fatal("sources created a database")
	}
}

func TestInitRefusesForeignFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	content := []byte(strings.Repeat("my notes\n", 20))
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"init", "sources"} {
		if code, _, errOut := run(t, "--db", path, cmd); code != 1 || !strings.Contains(errOut, "refusing") {
			t.Errorf("%s: code %d, stderr %q", cmd, code, errOut)
		}
	}
	if got, _ := os.ReadFile(path); string(got) != string(content) {
		t.Fatal("foreign file was modified")
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

func TestInitDoesNotCreateFoldersForDBFlag(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Bakup")
	if code, _, _ := run(t, "--db", filepath.Join(dir, "drivecat.db"), "init"); code != 1 {
		t.Fatalf("init in a missing folder: code %d, want 1", code)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("init created the folder given with --db")
	}
}

func TestInitCreatesDefaultFolder(t *testing.T) {
	base := t.TempDir()
	t.Setenv("DRIVECAT_DB", "")
	t.Setenv("LOCALAPPDATA", base)
	if code, _, errOut := run(t, "init"); code != 0 {
		t.Fatalf("init: %s", errOut)
	}
	if _, err := os.Stat(filepath.Join(base, "drivecat", "drivecat.db")); err != nil {
		t.Fatalf("default database not created: %v", err)
	}
}
