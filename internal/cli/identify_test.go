package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ThomasZeman/drivecat/internal/store"
	"github.com/ThomasZeman/drivecat/internal/volume"
)

func fakeIdentify(t *testing.T, id *volume.Identity, err error) *[]string {
	t.Helper()
	var calls []string
	orig := identifyFunc
	identifyFunc = func(p string) (*volume.Identity, error) {
		calls = append(calls, p)
		return id, err
	}
	t.Cleanup(func() { identifyFunc = orig })
	return &calls
}

func usbIdentity() *volume.Identity {
	hdd := true
	return &volume.Identity{
		Kind: volume.KindDisk, Fingerprint: "disk:gpt:{x}/aabbccdd", Input: `E:\Photos`,
		MountedAs: `E:\`, RelRoot: "/Photos", BusType: "USB", DiskModel: "WD Elements",
		DiskSize: 2 << 40, DiskNumber: 2, PartitionStyle: "GPT", PartitionID: "gpt:{x}",
		FSType: "NTFS", FSLabel: "Backup", FSSerial: "11223344aabbccdd", SeekPenalty: &hdd,
		Warnings: []string{"disk serial: not reported"},
	}
}

func TestIdentifyUnknownDoesNotCreateDB(t *testing.T) {
	calls := fakeIdentify(t, usbIdentity(), nil)
	db := filepath.Join(t.TempDir(), "drivecat.db")

	code, out, errOut := run(t, "--db", db, "identify", `E:\Photos`)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	for _, want := range []string{"disk:gpt:{x}/aabbccdd", "not in the database yet", "/Photos",
		"WD Elements, USB, 2.0 TiB, spinning (HDD), disk 2 on this PC", `NTFS "Backup"`, "Warning"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !reflect.DeepEqual(*calls, []string{`E:\Photos`}) {
		t.Errorf("identify called with %v", *calls)
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Errorf("identify created the database (stat err %v)", err)
	}
}

func TestIdentifyKnownSource(t *testing.T) {
	fakeIdentify(t, usbIdentity(), nil)
	db := filepath.Join(t.TempDir(), "drivecat.db")
	s, err := store.Create(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	// Until scan adds sources the real way, insert one directly.
	raw, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	now := store.Timestamp(time.Now())
	if _, err := raw.Exec(`INSERT INTO sources (kind, fingerprint, label, first_seen, last_seen)
		VALUES ('disk', 'disk:gpt:{x}/aabbccdd', 'WD 2TB black', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	code, out, errOut := run(t, "--db", db, "identify", "--json", `E:\Photos`)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got["known_source_label"] != "WD 2TB black" || got["fingerprint"] != "disk:gpt:{x}/aabbccdd" ||
		got["rel_root"] != "/Photos" {
		t.Errorf("JSON fields: %v", got)
	}
}

func TestIdentifyFlagAfterPath(t *testing.T) {
	fakeIdentify(t, usbIdentity(), nil)
	db := filepath.Join(t.TempDir(), "drivecat.db")
	code, out, _ := run(t, "--db", db, "identify", `E:\`, "--json")
	if code != 0 || !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Fatalf("code %d, out %q", code, out)
	}
}

func TestIdentifyErrors(t *testing.T) {
	db := filepath.Join(t.TempDir(), "drivecat.db")
	fakeIdentify(t, nil, errors.New("boom"))
	if code, _, errOut := run(t, "--db", db, "identify", `E:\`); code != 1 || !strings.Contains(errOut, "boom") {
		t.Errorf("identify error: code %d, %q", code, errOut)
	}
	for _, args := range [][]string{{"identify"}, {"identify", "a", "b"}, {"identify", "--nope", "a"}} {
		if code, _, _ := run(t, append([]string{"--db", db}, args...)...); code != 2 {
			t.Errorf("%v: code %d, want 2", args, code)
		}
	}
}

func TestParseInterleaved(t *testing.T) {
	cases := []struct {
		args []string
		pos  []string
		json bool
	}{
		{[]string{"a"}, []string{"a"}, false},
		{[]string{"--json", "a"}, []string{"a"}, true},
		{[]string{"a", "--json"}, []string{"a"}, true},
		{[]string{"a", "--json", "b"}, []string{"a", "b"}, true},
		{[]string{"--", "--json"}, []string{"--json"}, false},
		{[]string{"a", "--", "-b", "--json"}, []string{"a", "-b", "--json"}, false},
	}
	for _, c := range cases {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		j := fs.Bool("json", false, "")
		pos, err := parseInterleaved(fs, c.args)
		if err != nil || !reflect.DeepEqual(pos, c.pos) || *j != c.json {
			t.Errorf("%v: pos %v json %v err %v; want %v %v", c.args, pos, *j, err, c.pos, c.json)
		}
	}
}
