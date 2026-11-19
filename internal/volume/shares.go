package volume

import (
	"sort"
	"strings"
)

// Share is a shared folder offered by a server.
type Share struct {
	Name   string `json:"name"`
	Remark string `json:"remark,omitempty"`
	Path   string `json:"path"` // \\server\name
}

// Share types as NetShareEnum reports them (STYPE_*). The low byte is the
// kind; the high bits mark admin and temporary shares.
const (
	stypeDiskTree  = 0
	stypeMask      = 0xff
	stypeSpecial   = 0x80000000 // C$, ADMIN$, IPC$
	stypeTemporary = 0x40000000
)

// ServerOnly reports whether p names a server without a share, like
// \\nas or \\192.168.1.20\, and returns the server.
func ServerOnly(p string) (server string, ok bool) {
	q := strings.ReplaceAll(p, "/", `\`)
	switch {
	case hasPrefixFold(q, `\\?\UNC\`):
		q = q[len(`\\?\UNC\`):]
	case strings.HasPrefix(q, `\\?\`), strings.HasPrefix(q, `\\.\`):
		return "", false
	case strings.HasPrefix(q, `\\`):
		q = q[2:]
	default:
		return "", false
	}
	q = strings.TrimRight(q, `\`)
	if q == "" || strings.Contains(q, `\`) {
		return "", false
	}
	return q, true
}

// scannableShares keeps the shares worth scanning: ordinary folder shares.
// Printers, devices, IPC$, admin shares (C$, ADMIN$) and other hidden
// shares ending in $ are left out; a hidden share can still be scanned by
// its full path.
func scannableShares(server string, all []rawShare) []Share {
	var out []Share
	for _, s := range all {
		if s.typ&stypeMask != stypeDiskTree || s.typ&(stypeSpecial|stypeTemporary) != 0 ||
			strings.HasSuffix(s.name, "$") || s.name == "" {
			continue
		}
		out = append(out, Share{Name: s.name, Remark: s.remark, Path: `\\` + server + `\` + s.name})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// rawShare is one entry as the server lists it.
type rawShare struct {
	name, remark string
	typ          uint32
}
