//go:build windows

package volume

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ThomasZeman/drivecat/internal/readonly"
)

const (
	storageDeviceProperty        = 0
	storageDeviceSeekPenaltyProp = 7
	fileIDInfoClass              = 18 // FILE_INFO_BY_HANDLE_CLASS FileIdInfo
)

var (
	mpr                   = windows.NewLazySystemDLL("mpr.dll")
	procWNetGetConnection = mpr.NewProc("WNetGetConnectionW")
)

// Identify finds the drive or share behind path and reads its identifiers.
// It only reads: nothing is written to the drive.
func Identify(path string) (*Identity, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, err
	}
	abs = strings.TrimPrefix(abs, `\\?\`) // filepath.Abs may add it for long paths; UNC keeps its own form

	if server, share, rest, ok := splitUNC(abs); ok {
		return identifySMB(path, server, share, rest)
	}

	// A drive letter mapped to a share is a network source, not a disk.
	if len(abs) >= 2 && abs[1] == ':' {
		root := abs[:2] + `\`
		if windows.GetDriveType(windows.StringToUTF16Ptr(root)) == windows.DRIVE_REMOTE {
			unc, err := mappedDriveTarget(abs[:2])
			if err != nil {
				return nil, fmt.Errorf("resolve mapped drive %s: %w", abs[:2], err)
			}
			server, share, rest, ok := splitUNC(unc + `\` + strings.TrimLeft(abs[2:], `\`))
			if !ok {
				return nil, fmt.Errorf("mapped drive %s points to %q, which is not \\\\server\\share", abs[:2], unc)
			}
			return identifySMB(path, server, share, rest)
		}
	}
	return identifyDisk(path, abs)
}

func identifySMB(input, server, share, rest string) (*Identity, error) {
	id := &Identity{
		Kind:        KindSMB,
		Fingerprint: smbFingerprint(server, share),
		Input:       input,
		MountedAs:   `\\` + server + `\` + share,
		RelRoot:     relRoot(rest),
		BusType:     "SMB",
		DiskNumber:  -1,
		SMBServer:   strings.ToLower(server),
		SMBShare:    strings.ToLower(share),
	}
	if label, serial, fs, err := volumeInformation(id.MountedAs + `\`); err == nil {
		id.FSLabel, id.FSType = label, fs
		id.FSSerial = fmt.Sprintf("%08x", serial)
	} else {
		id.Warnings = append(id.Warnings, "volume information: "+err.Error())
	}
	id.MarkerID = readMarker(id.MountedAs + `\`)
	return id, nil
}

func identifyDisk(input, abs string) (*Identity, error) {
	mount, err := volumePathName(abs)
	if err != nil {
		return nil, fmt.Errorf("find mount point of %s: %w", abs, err)
	}
	id := &Identity{
		Kind:       KindDisk,
		Input:      input,
		MountedAs:  mount,
		RelRoot:    relRoot(abs[len(mount):]),
		DiskNumber: -1,
	}
	warn := func(what string, err error) { id.Warnings = append(id.Warnings, what+": "+err.Error()) }

	guidPath, err := volumeNameForMountPoint(mount)
	if err != nil {
		return nil, fmt.Errorf("volume of %s: %w", mount, err)
	}
	id.VolumeGUIDPath = guidPath

	label, serial32, fs, err := volumeInformation(mount)
	if err != nil {
		return nil, fmt.Errorf("volume information of %s: %w", mount, err)
	}
	id.FSLabel, id.FSType = label, fs
	// The fingerprint always uses the 32-bit serial: every file system has
	// it, and it comes from a call that does not fail where the 64-bit one
	// might, so the same drive cannot end up with two fingerprints.
	fpSerial := fmt.Sprintf("%08x", serial32)
	id.FSSerial = fpSerial
	// NTFS and ReFS also have a 64-bit serial (the 32-bit one is its low
	// half). It is recorded for information only.
	if fs == "NTFS" || fs == "ReFS" {
		if s64, err := volumeSerial64(mount); err == nil {
			id.FSSerial = fmt.Sprintf("%016x", s64)
		} else {
			warn("64-bit volume serial", err)
		}
	}

	// The volume device: \\?\Volume{...} without the trailing backslash.
	vol, err := openDevice(strings.TrimSuffix(guidPath, `\`))
	if err != nil {
		return nil, fmt.Errorf("open volume %s: %w", guidPath, err)
	}
	defer windows.CloseHandle(vol)

	var mbrSignature string
	pi, piErr := partitionInfoOf(vol)
	if piErr != nil {
		warn("partition information", piErr)
	} else {
		id.PartitionStyle, id.PartitionOffset = pi.Style, pi.Offset
	}

	if n, err := deviceNumber(vol); err != nil {
		// Volumes spanning disks (dynamic disks, Storage Spaces) have no
		// single disk; the volume itself still has its serial.
		warn("disk number", err)
	} else {
		id.DiskNumber = int(n)
		mbrSignature = readDiskDetails(id, n, warn)
	}

	if piErr == nil {
		id.PartitionID = partitionID(pi, mbrSignature)
	}
	if id.Fingerprint, err = diskFingerprint(id.PartitionID, fpSerial); err != nil {
		return nil, err
	}
	id.MarkerID = readMarker(mount)
	return id, nil
}

// readDiskDetails fills in what the physical disk reports about itself and
// returns its MBR signature, if it has one. Failures become warnings.
func readDiskDetails(id *Identity, n uint32, warn func(string, error)) (mbrSignature string) {
	disk, err := openDevice(fmt.Sprintf(`\\.\PhysicalDrive%d`, n))
	if err != nil {
		warn("open disk", err)
		return ""
	}
	defer windows.CloseHandle(disk)

	if b, err := queryProperty(disk, storageDeviceProperty); err != nil {
		warn("disk description", err)
	} else if d, err := parseDeviceDescriptor(b); err != nil {
		warn("disk description", err)
	} else {
		id.BusType, id.DiskModel, id.DiskSerial = d.BusType, diskModel(d), d.Serial
	}

	if b, err := queryProperty(disk, storageDeviceSeekPenaltyProp); err == nil && len(b) >= 9 {
		// DEVICE_SEEK_PENALTY_DESCRIPTOR: Version, Size uint32, IncursSeekPenalty bool
		p := b[8] != 0
		id.SeekPenalty = &p
	}

	if b, err := ioctl(disk, ioctlDiskGetDriveGeometryEx, nil, 256); err != nil {
		warn("disk size", err)
	} else if len(b) >= 32 {
		// DISK_GEOMETRY_EX: DISK_GEOMETRY (24 bytes), then DiskSize int64
		id.DiskSize = int64(binary.LittleEndian.Uint64(b[24:32]))
	}

	if b, err := ioctl(disk, ioctlDiskGetDriveLayoutEx, nil, 64<<10); err != nil {
		warn("disk layout", err)
	} else if style, diskID, err := parseDriveLayoutEx(b); err != nil {
		warn("disk layout", err)
	} else {
		id.DiskID = diskID
		if style == "MBR" {
			mbrSignature = diskID
		}
	}
	return mbrSignature
}

// openDevice opens a volume or disk for queries only (no read access), which
// works without administrator rights.
func openDevice(name string) (windows.Handle, error) {
	return windows.CreateFile(windows.StringToUTF16Ptr(name), 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
}

// ioctl is the only place drivecat calls DeviceIoControl. It refuses every
// code that is not one of the known read-only queries, so a later edit
// cannot slip in a code that changes a drive.
func ioctl(h windows.Handle, code uint32, in []byte, outSize int) ([]byte, error) {
	if err := checkIoctl(code); err != nil {
		return nil, err
	}
	out := make([]byte, outSize)
	var inPtr *byte
	if len(in) > 0 {
		inPtr = &in[0]
	}
	var n uint32
	if err := windows.DeviceIoControl(h, code, inPtr, uint32(len(in)), &out[0], uint32(len(out)), &n, nil); err != nil {
		return nil, err
	}
	return out[:n], nil
}

func queryProperty(h windows.Handle, propertyID uint32) ([]byte, error) {
	// STORAGE_PROPERTY_QUERY: PropertyId, QueryType (PropertyStandardQuery = 0), AdditionalParameters[1]
	q := make([]byte, 12)
	binary.LittleEndian.PutUint32(q[0:4], propertyID)
	return ioctl(h, ioctlStorageQueryProperty, q, 4096)
}

func partitionInfoOf(vol windows.Handle) (partitionInfo, error) {
	b, err := ioctl(vol, ioctlDiskGetPartitionInfoEx, nil, 256)
	if err != nil {
		return partitionInfo{}, err
	}
	return parsePartitionInfoEx(b)
}

func deviceNumber(vol windows.Handle) (uint32, error) {
	// STORAGE_DEVICE_NUMBER: DeviceType, DeviceNumber, PartitionNumber uint32
	b, err := ioctl(vol, ioctlStorageGetDeviceNumber, nil, 12)
	if err != nil {
		return 0, err
	}
	if len(b) < 8 {
		return 0, fmt.Errorf("STORAGE_DEVICE_NUMBER too short: %d bytes", len(b))
	}
	return binary.LittleEndian.Uint32(b[4:8]), nil
}

func volumePathName(p string) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	if err := windows.GetVolumePathName(windows.StringToUTF16Ptr(p), &buf[0], uint32(len(buf))); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf), nil
}

func volumeNameForMountPoint(mount string) (string, error) {
	buf := make([]uint16, 64)
	if err := windows.GetVolumeNameForVolumeMountPoint(windows.StringToUTF16Ptr(mount), &buf[0], uint32(len(buf))); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf), nil
}

func volumeInformation(root string) (label string, serial uint32, fs string, err error) {
	labelBuf := make([]uint16, windows.MAX_PATH+1)
	fsBuf := make([]uint16, windows.MAX_PATH+1)
	var maxComponent, flags uint32
	err = windows.GetVolumeInformation(windows.StringToUTF16Ptr(root), &labelBuf[0], uint32(len(labelBuf)),
		&serial, &maxComponent, &flags, &fsBuf[0], uint32(len(fsBuf)))
	return windows.UTF16ToString(labelBuf), serial, windows.UTF16ToString(fsBuf), err
}

// volumeSerial64 reads the full 64-bit serial through FILE_ID_INFO of the
// root folder, which unlike FSCTL_GET_NTFS_VOLUME_DATA needs no admin rights.
func volumeSerial64(mount string) (uint64, error) {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(mount), windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	// FILE_ID_INFO. It must be 8-byte aligned, or Windows fails with
	// ERROR_NOACCESS; a struct with a uint64 first guarantees that, a byte
	// array does not.
	var info struct {
		VolumeSerialNumber uint64
		FileID             [16]byte
	}
	if err := windows.GetFileInformationByHandleEx(h, fileIDInfoClass,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return 0, err
	}
	return info.VolumeSerialNumber, nil
}

func mappedDriveTarget(drive string) (string, error) {
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	r, _, _ := procWNetGetConnection.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(drive))),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return "", windows.Errno(r)
	}
	return windows.UTF16ToString(buf), nil
}

// readMarker returns the UUID in the root's marker file, or "". It reads
// through the readonly package, so an offline or cloud marker file is
// skipped instead of recalled.
func readMarker(root string) string {
	f, err := readonly.Open(filepath.Join(root, MarkerFile))
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil || len(b) > 256 {
		return ""
	}
	return strings.TrimSpace(string(b))
}
