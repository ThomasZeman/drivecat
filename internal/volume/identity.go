// Package volume finds out which drive or network share a path lives on and
// derives a fingerprint that recognizes it again, independent of the drive
// letter, the USB port or the PC it is plugged into.
package volume

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Kinds of source.
const (
	KindDisk = "disk"
	KindSMB  = "smb"
)

// MarkerFile is the optional file in a drive's root that holds a UUID, to
// tell apart sector-by-sector clones. drivecat only reads it, never writes
// it: placing one is up to the owner, by hand.
const MarkerFile = ".drivecat-id"

// Identity is everything drivecat knows about the drive or share behind a
// path. Only Kind and Fingerprint identify it; the rest is recorded for the
// owner to recognize the drive and for scan defaults.
type Identity struct {
	Kind        string `json:"kind"`
	Fingerprint string `json:"fingerprint"`

	Input     string `json:"input"`      // the path as given
	MountedAs string `json:"mounted_as"` // E:\, C:\mnt\backup\ or \\server\share
	RelRoot   string `json:"rel_root"`   // the path relative to the source, '/'-separated, "/" for the root

	VolumeGUIDPath string `json:"volume_guid_path,omitempty"` // per PC, information only

	BusType    string `json:"bus_type,omitempty"`
	DiskModel  string `json:"disk_model,omitempty"`
	DiskSerial string `json:"disk_serial,omitempty"`
	DiskNumber int    `json:"disk_number"` // -1 if unknown
	DiskSize   int64  `json:"disk_size,omitempty"`
	DiskID     string `json:"disk_id,omitempty"` // GPT disk GUID or MBR signature

	PartitionStyle  string `json:"partition_style,omitempty"` // GPT, MBR or RAW
	PartitionID     string `json:"partition_id,omitempty"`
	PartitionOffset int64  `json:"partition_offset,omitempty"`

	FSType   string `json:"fs_type,omitempty"`
	FSLabel  string `json:"fs_label,omitempty"`
	FSSerial string `json:"fs_serial,omitempty"`

	SMBServer string `json:"smb_server,omitempty"`
	SMBShare  string `json:"smb_share,omitempty"`

	// SeekPenalty is true for spinning drives, false for SSDs, nil if
	// Windows does not say. The scanner uses it to pick its worker count.
	SeekPenalty *bool `json:"seek_penalty,omitempty"`

	MarkerID string `json:"marker_id,omitempty"`

	// Warnings lists details that could not be read. They do not prevent
	// identification; USB enclosures in particular often hide disk details.
	Warnings []string `json:"warnings,omitempty"`
}

// ErrNoFingerprint means neither a partition id nor a file system serial
// could be read, so the drive cannot be recognized again.
var ErrNoFingerprint = errors.New("cannot fingerprint this drive: no partition id and no file system serial")

// diskFingerprint builds the fingerprint of a local volume from the
// identifiers stored on the drive itself.
func diskFingerprint(partitionID, fsSerial string) (string, error) {
	if fsSerial == "" {
		return "", ErrNoFingerprint
	}
	if partitionID == "" {
		partitionID = "raw"
	}
	return "disk:" + partitionID + "/" + fsSerial, nil
}

func smbFingerprint(server, share string) string {
	return "smb:" + strings.ToLower(server) + "/" + strings.ToLower(share)
}

// splitUNC splits \\server\share\rest into its parts. It accepts the
// \\?\UNC\ long-path form too. rest has no leading separator.
func splitUNC(p string) (server, share, rest string, ok bool) {
	switch {
	case hasPrefixFold(p, `\\?\UNC\`):
		p = p[len(`\\?\UNC\`):]
	case strings.HasPrefix(p, `\\?\`), strings.HasPrefix(p, `\\.\`):
		return "", "", "", false
	case strings.HasPrefix(p, `\\`):
		p = p[2:]
	default:
		return "", "", "", false
	}
	parts := strings.SplitN(p, `\`, 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	if len(parts) == 3 {
		rest = strings.Trim(parts[2], `\`)
	}
	return parts[0], parts[1], rest, true
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// relRoot turns the part of a path below its mount point into drivecat's
// form: '/'-separated with a leading '/', and "/" for the root itself.
func relRoot(belowMount string) string {
	r := strings.Trim(strings.ReplaceAll(belowMount, `\`, "/"), "/")
	return "/" + r
}

// formatGUID renders a Windows GUID (mixed-endian, 16 bytes) in its usual
// lower-case {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} form.
func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("{%08x-%04x-%04x-%x-%x}",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8:10], b[10:16])
}

// Partition styles as Windows numbers them (PARTITION_STYLE).
const (
	partitionStyleMBR = 0
	partitionStyleGPT = 1
	partitionStyleRAW = 2
)

// partitionInfo is the part of PARTITION_INFORMATION_EX drivecat uses.
type partitionInfo struct {
	Style  string
	Offset int64
	Number uint32
	GPTID  string // the partition's unique GUID, GPT only
}

// parsePartitionInfoEx decodes PARTITION_INFORMATION_EX:
//
//	0  PartitionStyle   uint32 (+4 padding)
//	8  StartingOffset   int64
//	16 PartitionLength  int64
//	24 PartitionNumber  uint32
//	28 RewritePartition, IsServicePartition (+2 padding)
//	32 union; GPT: PartitionType GUID, then PartitionId GUID at 48
func parsePartitionInfoEx(b []byte) (partitionInfo, error) {
	if len(b) < 32 {
		return partitionInfo{}, fmt.Errorf("PARTITION_INFORMATION_EX too short: %d bytes", len(b))
	}
	pi := partitionInfo{
		Offset: int64(binary.LittleEndian.Uint64(b[8:16])),
		Number: binary.LittleEndian.Uint32(b[24:28]),
	}
	switch binary.LittleEndian.Uint32(b[0:4]) {
	case partitionStyleMBR:
		pi.Style = "MBR"
	case partitionStyleGPT:
		pi.Style = "GPT"
		if len(b) < 64 {
			return partitionInfo{}, fmt.Errorf("GPT PARTITION_INFORMATION_EX too short: %d bytes", len(b))
		}
		pi.GPTID = formatGUID(b[48:64])
	case partitionStyleRAW:
		pi.Style = "RAW"
	default:
		return partitionInfo{}, fmt.Errorf("unknown partition style %d", binary.LittleEndian.Uint32(b[0:4]))
	}
	return pi, nil
}

// parseDriveLayoutEx decodes the header of DRIVE_LAYOUT_INFORMATION_EX and
// returns the disk's identifier: the GPT disk GUID or the MBR signature.
//
//	0 PartitionStyle uint32
//	4 PartitionCount uint32
//	8 union; MBR: Signature uint32; GPT: DiskId GUID
func parseDriveLayoutEx(b []byte) (style, diskID string, err error) {
	if len(b) < 24 {
		return "", "", fmt.Errorf("DRIVE_LAYOUT_INFORMATION_EX too short: %d bytes", len(b))
	}
	switch binary.LittleEndian.Uint32(b[0:4]) {
	case partitionStyleMBR:
		return "MBR", fmt.Sprintf("%08x", binary.LittleEndian.Uint32(b[8:12])), nil
	case partitionStyleGPT:
		return "GPT", formatGUID(b[8:24]), nil
	case partitionStyleRAW:
		return "RAW", "", nil
	}
	return "", "", fmt.Errorf("unknown partition style %d", binary.LittleEndian.Uint32(b[0:4]))
}

// partitionID is the partition part of a disk fingerprint: the GPT
// partition GUID, or for MBR the disk signature and the partition's offset,
// since MBR partitions have no id of their own.
func partitionID(pi partitionInfo, mbrSignature string) string {
	switch pi.Style {
	case "GPT":
		if pi.GPTID != "" {
			return "gpt:" + pi.GPTID
		}
	case "MBR":
		if mbrSignature != "" {
			return fmt.Sprintf("mbr:%s@%d", mbrSignature, pi.Offset)
		}
	}
	return ""
}

// deviceDescriptor is the part of STORAGE_DEVICE_DESCRIPTOR drivecat uses.
type deviceDescriptor struct {
	Vendor, Product, Serial string
	BusType                 string
	Removable               bool
}

// parseDeviceDescriptor decodes STORAGE_DEVICE_DESCRIPTOR:
//
//	0  Version, 4 Size uint32
//	8  DeviceType, DeviceTypeModifier byte; 10 RemovableMedia, CommandQueueing bool
//	12 VendorIdOffset, 16 ProductIdOffset, 20 ProductRevisionOffset,
//	24 SerialNumberOffset, 28 BusType, 32 RawPropertiesLength uint32
//
// The offsets point to NUL-terminated ASCII strings inside b; 0 means absent.
func parseDeviceDescriptor(b []byte) (deviceDescriptor, error) {
	if len(b) < 36 {
		return deviceDescriptor{}, fmt.Errorf("STORAGE_DEVICE_DESCRIPTOR too short: %d bytes", len(b))
	}
	str := func(at int) string {
		off := int(binary.LittleEndian.Uint32(b[at : at+4]))
		if off == 0 || off >= len(b) {
			return ""
		}
		end := off
		for end < len(b) && b[end] != 0 {
			end++
		}
		return strings.TrimSpace(string(b[off:end]))
	}
	return deviceDescriptor{
		Removable: b[10] != 0,
		Vendor:    str(12),
		Product:   str(16),
		Serial:    str(24),
		BusType:   busTypeName(binary.LittleEndian.Uint32(b[28:32])),
	}, nil
}

// busTypeName names a STORAGE_BUS_TYPE value.
func busTypeName(t uint32) string {
	names := map[uint32]string{
		1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394", 5: "SSA", 6: "Fibre", 7: "USB", 8: "RAID",
		9: "iSCSI", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "Virtual",
		15: "FileBackedVirtual", 16: "Spaces", 17: "NVMe", 18: "SCM", 19: "UFS",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("Unknown(%d)", t)
}

// diskModel joins vendor and product, which many drives report as one
// string in the product field with an empty or generic vendor.
func diskModel(d deviceDescriptor) string {
	return strings.TrimSpace(strings.TrimSpace(d.Vendor) + " " + strings.TrimSpace(d.Product))
}
