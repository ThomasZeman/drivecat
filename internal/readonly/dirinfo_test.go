package readonly

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"
)

// record builds one FILE_FULL_DIR_INFO record, padded to 8 bytes.
func record(name []uint16, size int64, ft uint64, attrs uint32, last bool) []byte {
	n := 68 + 2*len(name)
	padded := (n + 7) &^ 7
	b := make([]byte, padded)
	if !last {
		binary.LittleEndian.PutUint32(b[0:], uint32(padded))
	}
	binary.LittleEndian.PutUint64(b[24:], ft)
	binary.LittleEndian.PutUint64(b[40:], uint64(size))
	binary.LittleEndian.PutUint32(b[56:], attrs)
	binary.LittleEndian.PutUint32(b[60:], uint32(2*len(name)))
	for i, u := range name {
		binary.LittleEndian.PutUint16(b[68+2*i:], u)
	}
	return b
}

func TestParseFullDirInfo(t *testing.T) {
	// 2004-07-01 12:00:00 UTC as a FILETIME
	when := time.Date(2004, 7, 1, 12, 0, 0, 0, time.UTC)
	ft := uint64(when.Unix())*1e7 + 116444736000000000

	var buf []byte
	buf = append(buf, record(utf16.Encode([]rune(".")), 0, ft, 0x10, false)...)
	buf = append(buf, record(utf16.Encode([]rune("..")), 0, ft, 0x10, false)...)
	buf = append(buf, record(utf16.Encode([]rune("Urlaub 2004 – Küste 📷.jpg")), 123456, ft, 0x20, false)...)
	buf = append(buf, record([]uint16{'a', 0xd800, 'b'}, 1, ft, 0x20, true)...)
	buf = append(buf, make([]byte, 100)...) // garbage after the last record is ignored

	got, err := parseFullDirInfo(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	e := got[0]
	if e.Name != "Urlaub 2004 – Küste 📷.jpg" || e.Size != 123456 || !e.ModTime.Equal(when) || e.Attrs != 0x20 ||
		e.BadName {
		t.Errorf("entry 0 = %+v", e)
	}
	if !got[1].BadName {
		t.Errorf("unpaired surrogate not flagged: %+v", got[1])
	}
}

func TestParseFullDirInfoRejectsMalformed(t *testing.T) {
	good := record(utf16.Encode([]rune("x.jpg")), 1, 0, 0x20, true)
	for name, buf := range map[string][]byte{
		"short": good[:40],
		"name too long": func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[60:], 4000)
			return b
		}(),
		"odd name":    func() []byte { b := append([]byte(nil), good...); binary.LittleEndian.PutUint32(b[60:], 3); return b }(),
		"next inside": func() []byte { b := append([]byte(nil), good...); binary.LittleEndian.PutUint32(b[0:], 8); return b }(),
	} {
		if _, err := parseFullDirInfo(buf, nil); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestFiletimeToTime(t *testing.T) {
	if got := filetimeToTime(116444736000000000); !got.Equal(time.Unix(0, 0)) {
		t.Errorf("Unix epoch: %v", got)
	}
	if got := filetimeToTime(0); got.Year() != 1601 {
		t.Errorf("zero FILETIME: %v", got)
	}
	if got := filetimeToTime(1 << 63); !got.IsZero() {
		t.Errorf("corrupt FILETIME: %v, want zero time", got)
	}
}
