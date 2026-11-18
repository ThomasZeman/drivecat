//go:build windows

package volume

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run against the real system drive and the temp folder, so
// they check the Windows calls and the struct layouts end to end.

func TestIdentifySystemDrive(t *testing.T) {
	sys := os.Getenv("SystemDrive") + `\`
	id, err := Identify(sys)
	if err != nil {
		t.Fatalf("Identify(%s): %v", sys, err)
	}
	t.Logf("%+v", *id)

	if id.Kind != KindDisk || id.RelRoot != "/" || !strings.EqualFold(id.MountedAs, sys) {
		t.Errorf("kind/root/mount: %s %s %s", id.Kind, id.RelRoot, id.MountedAs)
	}
	if !strings.HasPrefix(id.Fingerprint, "disk:") {
		t.Errorf("fingerprint %q", id.Fingerprint)
	}
	if id.FSType == "NTFS" {
		if len(id.FSSerial) != 16 {
			t.Errorf("NTFS should give a 64-bit serial, got %q (warnings %v)", id.FSSerial, id.Warnings)
		}
		// The fingerprint carries the low 32 bits of it.
		if !strings.HasSuffix(id.Fingerprint, "/"+id.FSSerial[8:]) {
			t.Errorf("fingerprint %q does not end in the low half of %s", id.Fingerprint, id.FSSerial)
		}
	}
	if len(id.Warnings) > 0 {
		t.Errorf("unexpected warnings on the system drive: %v", id.Warnings)
	}
	if id.DiskNumber < 0 || id.BusType == "" || id.DiskSize <= 0 {
		t.Errorf("disk details missing: number %d, bus %q, size %d, warnings %v",
			id.DiskNumber, id.BusType, id.DiskSize, id.Warnings)
	}
	if id.PartitionStyle == "GPT" && !strings.HasPrefix(id.PartitionID, "gpt:{") {
		t.Errorf("GPT partition id %q", id.PartitionID)
	}
}

func TestIdentifySubfolderSameFingerprint(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	top, err := Identify(dir)
	if err != nil {
		t.Fatal(err)
	}
	deep, err := Identify(sub)
	if err != nil {
		t.Fatal(err)
	}
	if top.Fingerprint != deep.Fingerprint {
		t.Errorf("same volume, different fingerprints: %s vs %s", top.Fingerprint, deep.Fingerprint)
	}
	if !strings.HasSuffix(deep.RelRoot, "/a/b") || strings.Contains(deep.RelRoot, `\`) {
		t.Errorf("rel root %q", deep.RelRoot)
	}
}

func TestIdentifyMissingPath(t *testing.T) {
	if _, err := Identify(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("missing path accepted")
	}
}
