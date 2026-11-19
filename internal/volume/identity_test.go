package volume

import (
	"encoding/binary"
	"errors"
	"testing"
)

// guidBytes is {01234567-89ab-cdef-0123-456789abcdef} in Windows' layout.
var guidBytes = []byte{0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

const guidText = "{01234567-89ab-cdef-0123-456789abcdef}"

func TestFormatGUID(t *testing.T) {
	if got := formatGUID(guidBytes); got != guidText {
		t.Fatalf("formatGUID = %s, want %s", got, guidText)
	}
	if got := formatGUID(guidBytes[:15]); got != "" {
		t.Fatalf("short input: %q", got)
	}
}

func TestSplitUNC(t *testing.T) {
	cases := []struct {
		in                  string
		server, share, rest string
		ok                  bool
	}{
		{`\\nas\photos`, "nas", "photos", "", true},
		{`\\nas\photos\`, "nas", "photos", "", true},
		{`\\nas\photos\2010\summer\`, "nas", "photos", `2010\summer`, true},
		{`\\?\UNC\nas\photos\x`, "nas", "photos", "x", true},
		{`\\?\unc\nas\photos`, "nas", "photos", "", true},
		{`\\nas`, "", "", "", false},
		{`\\nas\`, "", "", "", false},
		{`\\?\C:\x`, "", "", "", false},
		{`\\.\PhysicalDrive0`, "", "", "", false},
		{`C:\x`, "", "", "", false},
	}
	for _, c := range cases {
		s, sh, r, ok := splitUNC(c.in)
		if s != c.server || sh != c.share || r != c.rest || ok != c.ok {
			t.Errorf("splitUNC(%q) = %q %q %q %v", c.in, s, sh, r, ok)
		}
	}
}

func TestRelRoot(t *testing.T) {
	for in, want := range map[string]string{
		"": "/", `\`: "/", `Photos`: "/Photos", `Photos\2010\`: "/Photos/2010", `\a\b`: "/a/b",
	} {
		if got := relRoot(in); got != want {
			t.Errorf("relRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFingerprints(t *testing.T) {
	fp, err := diskFingerprint("gpt:"+guidText, "00112233aabbccdd")
	if err != nil || fp != "disk:gpt:"+guidText+"/00112233aabbccdd" {
		t.Fatalf("GPT fingerprint = %q, %v", fp, err)
	}
	fp, err = diskFingerprint("", "aabbccdd")
	if err != nil || fp != "disk:raw/aabbccdd" {
		t.Fatalf("no partition id: %q, %v", fp, err)
	}
	if _, err := diskFingerprint("gpt:x", ""); !errors.Is(err, ErrNoFingerprint) {
		t.Fatalf("missing serial: %v", err)
	}
	if got := smbFingerprint("NAS", "Photos"); got != "smb:nas/photos" {
		t.Fatalf("smbFingerprint = %q", got)
	}
}

func TestParsePartitionInfoExGPT(t *testing.T) {
	b := make([]byte, 144)
	binary.LittleEndian.PutUint32(b[0:], partitionStyleGPT)
	binary.LittleEndian.PutUint64(b[8:], 16777216)
	binary.LittleEndian.PutUint32(b[24:], 2)
	copy(b[48:], guidBytes)

	pi, err := parsePartitionInfoEx(b)
	if err != nil {
		t.Fatal(err)
	}
	if pi.Style != "GPT" || pi.Offset != 16777216 || pi.Number != 2 || pi.GPTID != guidText {
		t.Fatalf("got %+v", pi)
	}
	if id := partitionID(pi, ""); id != "gpt:"+guidText {
		t.Fatalf("partitionID = %q", id)
	}
}

func TestParsePartitionInfoExMBR(t *testing.T) {
	b := make([]byte, 144)
	binary.LittleEndian.PutUint32(b[0:], partitionStyleMBR)
	binary.LittleEndian.PutUint64(b[8:], 1048576)

	pi, err := parsePartitionInfoEx(b)
	if err != nil || pi.Style != "MBR" || pi.Offset != 1048576 {
		t.Fatalf("got %+v, %v", pi, err)
	}
	if id := partitionID(pi, "1a2b3c4d"); id != "mbr:1a2b3c4d@1048576" {
		t.Fatalf("partitionID = %q", id)
	}
	if id := partitionID(pi, ""); id != "" {
		t.Fatalf("MBR without signature should give no id, got %q", id)
	}
}

func TestParsePartitionInfoExErrors(t *testing.T) {
	if _, err := parsePartitionInfoEx(make([]byte, 20)); err == nil {
		t.Error("short buffer accepted")
	}
	b := make([]byte, 144)
	binary.LittleEndian.PutUint32(b[0:], 9)
	if _, err := parsePartitionInfoEx(b); err == nil {
		t.Error("unknown style accepted")
	}
}

func TestParseDriveLayoutEx(t *testing.T) {
	b := make([]byte, 48)
	binary.LittleEndian.PutUint32(b[0:], partitionStyleMBR)
	binary.LittleEndian.PutUint32(b[8:], 0x1a2b3c4d)
	if style, id, err := parseDriveLayoutEx(b); err != nil || style != "MBR" || id != "1a2b3c4d" {
		t.Fatalf("MBR: %s %s %v", style, id, err)
	}

	b = make([]byte, 48)
	binary.LittleEndian.PutUint32(b[0:], partitionStyleGPT)
	copy(b[8:], guidBytes)
	if style, id, err := parseDriveLayoutEx(b); err != nil || style != "GPT" || id != guidText {
		t.Fatalf("GPT: %s %s %v", style, id, err)
	}
}

func TestParseDeviceDescriptor(t *testing.T) {
	b := make([]byte, 100)
	binary.LittleEndian.PutUint32(b[12:], 40) // vendor
	binary.LittleEndian.PutUint32(b[16:], 50) // product
	binary.LittleEndian.PutUint32(b[24:], 70) // serial
	binary.LittleEndian.PutUint32(b[28:], 7)  // USB
	b[10] = 1
	copy(b[40:], "WD  \x00")
	copy(b[50:], "Elements 25A2  \x00")
	copy(b[70:], " ABC123 \x00")

	d, err := parseDeviceDescriptor(b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Vendor != "WD" || d.Product != "Elements 25A2" || d.Serial != "ABC123" || d.BusType != "USB" || !d.Removable {
		t.Fatalf("got %+v", d)
	}
	if m := diskModel(d); m != "WD Elements 25A2" {
		t.Fatalf("diskModel = %q", m)
	}

	// Absent strings (offset 0) and offsets past the end are empty.
	b = make([]byte, 36)
	binary.LittleEndian.PutUint32(b[16:], 999)
	binary.LittleEndian.PutUint32(b[28:], 17)
	d, err = parseDeviceDescriptor(b)
	if err != nil || d.Vendor != "" || d.Product != "" || d.BusType != "NVMe" {
		t.Fatalf("got %+v, %v", d, err)
	}
	if diskModel(d) != "" {
		t.Fatalf("empty model expected")
	}

	// NVMe serials as Windows formats them lose the trailing dot.
	b = make([]byte, 100)
	binary.LittleEndian.PutUint32(b[24:], 40)
	copy(b[40:], "0025_38DC_21A6_AF8B.\x00")
	if d, err = parseDeviceDescriptor(b); err != nil || d.Serial != "0025_38DC_21A6_AF8B" {
		t.Fatalf("NVMe serial %q, %v", d.Serial, err)
	}
}

func TestBusTypeName(t *testing.T) {
	if busTypeName(11) != "SATA" || busTypeName(200) != "Unknown(200)" {
		t.Fatal("bus type names wrong")
	}
}

func TestCheckSourcePath(t *testing.T) {
	for _, p := range []string{
		`E:\`, `E:\Photos\2004`, `\\nas\photos`, `\\?\E:\Photos`, `\\?\UNC\nas\photos`,
		`relative\folder`, `E:\console.log`, `E:\COMPANY`, `E:\com10`, `E:\nullable`,
	} {
		if err := CheckSourcePath(p); err != nil {
			t.Errorf("CheckSourcePath(%q) = %v, want nil", p, err)
		}
	}
	for _, p := range []string{
		`COM3`, `com3`, `NUL`, `nul.txt`, `E:\Photos\AUX`, `E:\lpt1 `, `E:\COM¹`, `CONOUT$`,
		`\\.\PhysicalDrive0`, `\\.\C:`, `//./COM1`, `\\?\GLOBALROOT\Device\Harddisk0`,
		`\\?\Volume{00000000-0000-0000-0000-000000000000}\`, `\??\C:\`,
	} {
		if err := CheckSourcePath(p); !errors.Is(err, ErrDevicePath) {
			t.Errorf("CheckSourcePath(%q) = %v, want ErrDevicePath", p, err)
		}
	}
}
