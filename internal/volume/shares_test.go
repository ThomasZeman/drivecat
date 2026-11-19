package volume

import (
	"reflect"
	"testing"
)

func TestServerOnly(t *testing.T) {
	for in, want := range map[string]string{
		`\\192.168.1.20`:   "192.168.1.20",
		`\\nas\`:           "nas",
		`//nas`:            "nas",
		`\\?\UNC\nas`:      "nas",
		`\\nas\photos`:     "",
		`\\nas\photos\x`:   "",
		`C:\`:              "",
		`\\.\PhysicalDisk`: "",
		`\\`:               "",
	} {
		got, ok := ServerOnly(in)
		if got != want || ok != (want != "") {
			t.Errorf("ServerOnly(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestScannableShares(t *testing.T) {
	got := scannableShares("nas", []rawShare{
		{name: "photos", remark: "Family photos", typ: stypeDiskTree},
		{name: "Backup", typ: stypeDiskTree},
		{name: "IPC$", typ: 3 | stypeSpecial},
		{name: "C$", typ: stypeDiskTree | stypeSpecial},
		{name: "secret$", typ: stypeDiskTree},
		{name: "printer", typ: 1},
		{name: "tmp", typ: stypeDiskTree | stypeTemporary},
	})
	want := []Share{
		{Name: "Backup", Path: `\\nas\Backup`},
		{Name: "photos", Remark: "Family photos", Path: `\\nas\photos`},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}
