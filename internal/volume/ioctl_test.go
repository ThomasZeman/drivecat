package volume

import (
	"strings"
	"testing"
)

// TestIoctlCodesDecode decodes every allowed code from its number, so a
// mistyped constant or a SET code cannot hide behind a comment.
func TestIoctlCodesDecode(t *testing.T) {
	const (
		fileDeviceDisk        = 0x07
		fileDeviceMassStorage = 0x2d
		methodBuffered        = 0
	)
	want := map[uint32]ctlCode{
		ioctlStorageGetDeviceNumber: {fileDeviceMassStorage, fileAnyAccess, 0x420, methodBuffered},
		ioctlStorageQueryProperty:   {fileDeviceMassStorage, fileAnyAccess, 0x500, methodBuffered},
		ioctlDiskGetPartitionInfoEx: {fileDeviceDisk, fileAnyAccess, 0x12, methodBuffered},
		ioctlDiskGetDriveLayoutEx:   {fileDeviceDisk, fileAnyAccess, 0x14, methodBuffered},
		ioctlDiskGetDriveGeometryEx: {fileDeviceDisk, fileAnyAccess, 0x28, methodBuffered},
	}
	if len(want) != len(allowedIoctls) {
		t.Fatalf("allowedIoctls has %d codes, test knows %d: decode every new code here", len(allowedIoctls), len(want))
	}
	for code, w := range want {
		if got := decodeCtlCode(code); got != w {
			t.Errorf("%s (%#x) decodes to %+v, want %+v", allowedIoctls[code], code, got, w)
		}
		var in []byte
		if code == ioctlStorageQueryProperty {
			in = propertyQuery(storageDeviceProperty)
		}
		if err := checkIoctl(code, in); err != nil {
			t.Errorf("%s refused: %v", allowedIoctls[code], err)
		}
	}
}

func TestCheckIoctlRefusesWritesAndUnknown(t *testing.T) {
	cases := map[uint32]string{
		0x7C054: "requires handle access", // IOCTL_DISK_SET_DRIVE_LAYOUT_EX (read|write)
		0x7C100: "requires handle access", // IOCTL_DISK_DELETE_DRIVE_LAYOUT (read|write)
		0x90018: "not on drivecat's list", // FSCTL_LOCK_VOLUME: any access, but not allowed
		0x70000: "not on drivecat's list", // IOCTL_DISK_GET_DRIVE_GEOMETRY: harmless, but not listed
	}
	for code, want := range cases {
		err := checkIoctl(code, nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("checkIoctl(%#x) = %v, want error containing %q", code, err, want)
		}
	}
}

func TestCheckIoctlInput(t *testing.T) {
	for _, prop := range []uint32{storageDeviceProperty, storageDeviceSeekPenaltyProp} {
		if err := checkIoctl(ioctlStorageQueryProperty, propertyQuery(prop)); err != nil {
			t.Errorf("property %d refused: %v", prop, err)
		}
	}
	exists := propertyQuery(storageDeviceProperty)
	exists[4] = 1 // PropertyExistsQuery
	for name, in := range map[string][]byte{
		"no input":         nil,
		"other property":   propertyQuery(1),
		"other query type": exists,
		"longer input":     append(propertyQuery(storageDeviceProperty), 0, 0, 0, 0),
	} {
		if err := checkIoctl(ioctlStorageQueryProperty, in); err == nil {
			t.Errorf("query property with %s accepted", name)
		}
	}
	if err := checkIoctl(ioctlDiskGetDriveLayoutEx, []byte{1}); err == nil {
		t.Error("input to a code that takes none accepted")
	}
}
