// Package policy holds tests that enforce drivecat's hard rule: it never
// changes anything on the drives and shares it identifies or scans. The only
// thing drivecat writes is its own database, in internal/store.
//
// The check is type-based and works with allowlists. It loads drivecat's
// packages with full type information, so every identifier is resolved to
// the function, constant or variable it really refers to, whatever name,
// dot import or function value it is reached through. Then:
//
//   - each package may import only the packages listed for it;
//   - each use of a function, constant or variable from os, os/signal,
//     golang.org/x/sys/windows or modernc.org/sqlite must be listed for the
//     package that uses it;
//   - every windows.CreateFile call must pass constant read-only access,
//     OPEN_EXISTING and no delete-on-close, after constant folding;
//   - os.OpenFile may only create a new file (O_CREATE|O_EXCL);
//   - DeviceIoControl may only be called inside the IOCTL allowlist
//     function, and DLLs and DLL functions may only be loaded by listed
//     constant names;
//   - there is no cgo, assembly, go:linkname, or Go file that escapes the
//     check through build constraints.
//
// Adding to a list below is a deliberate act that a review must justify.
package policy

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

const module = "github.com/ThomasZeman/drivecat"

// allowedImports lists, per package, every package it may import. A new
// import, and therefore any new module, fails this test until it is listed.
var allowedImports = map[string][]string{
	"cmd/drivecat": {"context", "os", "os/signal", module + "/internal/cli"},
	"internal/cli": {"context", "encoding/json", "errors", "flag", "fmt", "io", "os", "path/filepath",
		"strings", "text/tabwriter", module + "/internal/store", module + "/internal/volume"},
	"internal/readonly": {"errors", "golang.org/x/sys/windows", "os", "strings"},
	"internal/store": {"bytes", "context", "database/sql", "database/sql/driver", "encoding/binary",
		"errors", "fmt", "io", "io/fs", "modernc.org/sqlite", "net/url", "os", "path/filepath", "strings",
		"time", module + "/internal/readonly"},
	"internal/volume": {"encoding/binary", "errors", "fmt", "golang.org/x/sys/windows", "io", "os",
		"path/filepath", "strings", "unsafe", module + "/internal/readonly"},
}

// sensitivePackages are the packages whose functions, constants and
// variables can reach the file system or the operating system directly.
// Every use of one of them must be listed in allowedUses.
var sensitivePackages = []string{"os", "os/signal", "golang.org/x/sys/windows", "modernc.org/sqlite"}

// allowedUses lists, per package, the sensitive functions, constants and
// variables it may use, by their full name. Each one only reads, or is
// needed for the database (internal/store only).
var allowedUses = map[string][]string{
	"cmd/drivecat": {
		"os.Args", "os.Exit", "os.Interrupt", "os.Stderr", "os.Stdout", "os/signal.NotifyContext",
	},
	"internal/cli": {
		"os.Getenv",
	},
	"internal/readonly": {
		// opening an existing file for reading (arguments checked below)
		"golang.org/x/sys/windows.CreateFile", "golang.org/x/sys/windows.OPEN_EXISTING",
		"golang.org/x/sys/windows.GENERIC_READ",
		"golang.org/x/sys/windows.FILE_SHARE_READ", "golang.org/x/sys/windows.FILE_SHARE_WRITE",
		"golang.org/x/sys/windows.FILE_SHARE_DELETE",
		"golang.org/x/sys/windows.FILE_FLAG_OPEN_NO_RECALL", "golang.org/x/sys/windows.FILE_FLAG_OPEN_REPARSE_POINT",
		"golang.org/x/sys/windows.FILE_FLAG_SEQUENTIAL_SCAN",
		// reading attributes
		"golang.org/x/sys/windows.GetFileAttributes", "golang.org/x/sys/windows.GetFileInformationByHandle",
		"golang.org/x/sys/windows.FILE_ATTRIBUTE_OFFLINE", "golang.org/x/sys/windows.FILE_ATTRIBUTE_RECALL_ON_OPEN",
		"golang.org/x/sys/windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS",
		"golang.org/x/sys/windows.FILE_ATTRIBUTE_REPARSE_POINT", "golang.org/x/sys/windows.FILE_ATTRIBUTE_DIRECTORY",
		"golang.org/x/sys/windows.FILE_ATTRIBUTE_DEVICE",
		"golang.org/x/sys/windows.UTF16PtrFromString", "golang.org/x/sys/windows.CloseHandle",
		"os.NewFile",
	},
	"internal/store": {
		// The database: create a new file only (checked below), make the
		// default folder, remove a database Create itself just made.
		"os.OpenFile", "os.O_RDWR", "os.O_CREATE", "os.O_EXCL", "os.Mkdir", "os.Remove",
		"os.Lstat", "os.Stat", "os.SameFile", "(*os.File).Close", "(*os.File).Stat",
		"(*modernc.org/sqlite.Driver).RegisterConnectionHook", "(*modernc.org/sqlite.Driver).Open",
		"(modernc.org/sqlite.AuthorizerRegisterer).RegisterAuthorizer",
		"modernc.org/sqlite.AuthAttach", "modernc.org/sqlite.AuthDetach", "modernc.org/sqlite.AuthPragma",
		"modernc.org/sqlite.AuthorizerDeny", "modernc.org/sqlite.AuthorizerOK",
	},
	"internal/volume": {
		// device handles without read or write access, for queries
		"golang.org/x/sys/windows.CreateFile", "golang.org/x/sys/windows.OPEN_EXISTING",
		"golang.org/x/sys/windows.FILE_SHARE_READ", "golang.org/x/sys/windows.FILE_SHARE_WRITE",
		"golang.org/x/sys/windows.FILE_SHARE_DELETE", "golang.org/x/sys/windows.FILE_READ_ATTRIBUTES",
		"golang.org/x/sys/windows.FILE_FLAG_BACKUP_SEMANTICS", "golang.org/x/sys/windows.CloseHandle",
		"golang.org/x/sys/windows.DeviceIoControl",
		// volume and drive information
		"golang.org/x/sys/windows.GetDriveType", "golang.org/x/sys/windows.DRIVE_REMOTE",
		"golang.org/x/sys/windows.GetVolumePathName", "golang.org/x/sys/windows.GetVolumeNameForVolumeMountPoint",
		"golang.org/x/sys/windows.GetVolumeInformation", "golang.org/x/sys/windows.GetFileInformationByHandleEx",
		"golang.org/x/sys/windows.MAX_LONG_PATH", "golang.org/x/sys/windows.MAX_PATH",
		// the one DLL function: resolving a mapped drive letter
		"golang.org/x/sys/windows.NewLazySystemDLL", "(*golang.org/x/sys/windows.LazyDLL).NewProc",
		"(*golang.org/x/sys/windows.LazyProc).Call",
		"golang.org/x/sys/windows.StringToUTF16Ptr", "golang.org/x/sys/windows.UTF16ToString",
		"os.Stat", "(*os.File).Close",
	},
}

// Arguments of the calls that are checked beyond their name.
var (
	// readAccessMask holds every access right drivecat may request:
	// GENERIC_READ (0x80000000), FILE_READ_DATA (1), FILE_READ_EA (8),
	// FILE_READ_ATTRIBUTES (0x80), READ_CONTROL (0x20000) and SYNCHRONIZE
	// (0x100000). Zero, for device queries, is allowed too.
	readAccessMask  = uint64(0x80000000 | 0x1 | 0x8 | 0x80 | 0x20000 | 0x100000)
	openExisting    = uint64(3)
	deleteOnClose   = uint64(0x04000000)
	allowedDLLs     = []string{"mpr.dll"}
	allowedDLLProcs = []string{"WNetGetConnectionW"}
	ioctlFunc       = "internal/volume.ioctl"
)

func TestNoWritesToSources(t *testing.T) {
	root := moduleRoot(t)
	covered := map[string]bool{}
	for _, goos := range []string{"windows", "linux"} {
		for _, pkg := range load(t, root, goos) {
			for _, f := range pkg.CompiledGoFiles {
				covered[filepath.Clean(f)] = true
			}
			checkPackage(t, pkg)
		}
	}
	checkFiles(t, root, covered)
}

func moduleRoot(t *testing.T) string {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s: %v", root, err)
	}
	return root
}

func load(t *testing.T, root, goos string) []*packages.Package {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax,
		Dir: root,
		Env: append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0"),
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("load packages for %s: %v", goos, err)
	}
	var out []*packages.Package
	for _, p := range pkgs {
		for _, e := range p.Errors {
			t.Errorf("%s (%s): %v", p.PkgPath, goos, e)
		}
		if p.PkgPath == module+"/internal/policy" {
			continue // test-only package
		}
		out = append(out, p)
	}
	if len(out) < 5 {
		t.Fatalf("only %d packages loaded for %s: is the load broken?", len(out), goos)
	}
	return out
}

func checkPackage(t *testing.T, pkg *packages.Package) {
	rel := strings.TrimPrefix(strings.TrimPrefix(pkg.PkgPath, module), "/")
	allowedImp, known := allowedImports[rel]
	if !known {
		t.Errorf("package %s is not in allowedImports: list what it may import", rel)
		return
	}
	for path := range pkg.Imports {
		if !slices.Contains(allowedImp, path) {
			t.Errorf("%s imports %s, which is not on its list", rel, path)
		}
	}

	uses := allowedUses[rel]
	info := pkg.TypesInfo
	for i, file := range pkg.Syntax {
		name := filepath.Base(pkg.CompiledGoFiles[i])
		where := func(pos token.Pos) string {
			return rel + "/" + name + ":" + strconv.Itoa(pkg.Fset.Position(pos).Line)
		}

		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if strings.HasPrefix(c.Text, "//go:linkname") {
					t.Errorf("%s: go:linkname reaches functions this check cannot see", where(c.Pos()))
				}
			}
		}

		enclosing := enclosingFuncs(file)
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				obj := info.Uses[n]
				if obj == nil || obj.Pkg() == nil || !slices.Contains(sensitivePackages, obj.Pkg().Path()) {
					return true
				}
				switch o := obj.(type) {
				case *types.TypeName, *types.PkgName:
					return true // naming a type or package changes nothing
				case *types.Var:
					if o.IsField() {
						return true // struct fields of values drivecat already holds
					}
				}
				k := fullName(obj)
				if !slices.Contains(uses, k) {
					t.Errorf("%s: %s is not on %s's list of allowed uses", where(n.Pos()), k, rel)
				}
				if k == "golang.org/x/sys/windows.DeviceIoControl" && rel+"."+enclosing(n.Pos()) != ioctlFunc {
					t.Errorf("%s: DeviceIoControl outside %s, which checks the IOCTL allowlist", where(n.Pos()),
						ioctlFunc)
				}
			case *ast.CallExpr:
				checkCall(t, info, n, where)
			}
			return true
		})
	}
}

// checkCall checks the arguments of the calls whose name alone does not
// make them safe.
func checkCall(t *testing.T, info *types.Info, call *ast.CallExpr, where func(token.Pos) string) {
	fn := calledFunc(info, call)
	if fn == nil {
		return
	}
	at := where(call.Pos())
	arg := func(i int) (constant.Value, bool) {
		if i >= len(call.Args) {
			return nil, false
		}
		tv, ok := info.Types[call.Args[i]]
		return tv.Value, ok && tv.Value != nil
	}
	num := func(i int) (uint64, bool) {
		v, ok := arg(i)
		if !ok {
			return 0, false
		}
		return constant.Uint64Val(constant.ToInt(v))
	}
	str := func(i int) (string, bool) {
		v, ok := arg(i)
		if !ok || v.Kind() != constant.String {
			return "", false
		}
		return constant.StringVal(v), true
	}

	switch fn.FullName() {
	case "golang.org/x/sys/windows.CreateFile":
		// CreateFile(name, access, share, sa, disposition, flags, template)
		if access, ok := num(1); !ok || access&^readAccessMask != 0 {
			t.Errorf("%s: CreateFile access must be a constant with read rights only", at)
		}
		if disp, ok := num(4); !ok || disp != openExisting {
			t.Errorf("%s: CreateFile disposition must be the constant OPEN_EXISTING", at)
		}
		if flags, ok := num(5); !ok || flags&deleteOnClose != 0 {
			t.Errorf("%s: CreateFile flags must be a constant without FILE_FLAG_DELETE_ON_CLOSE", at)
		}
	case "os.OpenFile":
		const need = os.O_CREATE | os.O_EXCL
		if flag, ok := num(1); !ok || int(flag)&need != need {
			t.Errorf("%s: os.OpenFile may only create a new file: constant flags with O_CREATE|O_EXCL", at)
		}
	case "golang.org/x/sys/windows.NewLazySystemDLL":
		if s, ok := str(0); !ok || !slices.Contains(allowedDLLs, strings.ToLower(s)) {
			t.Errorf("%s: DLL must be a constant name on the allowlist", at)
		}
	case "(*golang.org/x/sys/windows.LazyDLL).NewProc":
		if s, ok := str(0); !ok || !slices.Contains(allowedDLLProcs, s) {
			t.Errorf("%s: DLL function must be a constant name on the allowlist", at)
		}
	}
}

func calledFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = f
	case *ast.SelectorExpr:
		id = f.Sel
	default:
		return nil
	}
	fn, _ := info.Uses[id].(*types.Func)
	return fn
}

// enclosingFuncs returns a lookup from a position to the name of the
// function declaration around it ("" at package level). Methods are named
// Type.Method.
func enclosingFuncs(file *ast.File) func(token.Pos) string {
	type span struct {
		from, to token.Pos
		name     string
	}
	var spans []span
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) == 1 {
			name = recvName(fd.Recv.List[0].Type) + "." + name
		}
		spans = append(spans, span{fd.Pos(), fd.End(), name})
	}
	return func(p token.Pos) string {
		for _, s := range spans {
			if s.from <= p && p < s.to {
				return s.name
			}
		}
		return ""
	}
}

func recvName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.StarExpr:
		return recvName(e.X)
	case *ast.IndexExpr:
		return recvName(e.X)
	case *ast.Ident:
		return e.Name
	}
	return "?"
}

// fullName names an object the way allowedUses lists it: os.Remove,
// (*os.File).Write, golang.org/x/sys/windows.GENERIC_READ.
func fullName(obj types.Object) string {
	if fn, ok := obj.(*types.Func); ok {
		return fn.FullName()
	}
	return obj.Pkg().Path() + "." + obj.Name()
}

// checkFiles makes sure the type check saw every non-test Go file, and that
// there is no code it cannot see: cgo, assembly, C or prebuilt objects.
func checkFiles(t *testing.T, root string, covered map[string]bool) {
	var missed []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		switch ext := strings.ToLower(filepath.Ext(path)); ext {
		case ".go":
			if !strings.HasSuffix(path, "_test.go") && !covered[filepath.Clean(path)] {
				missed = append(missed, filepath.ToSlash(rel))
			}
		case ".s", ".c", ".h", ".cc", ".cpp", ".m", ".syso", ".a", ".o":
			t.Errorf("%s: %s files are code this check cannot see", filepath.ToSlash(rel), ext)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(missed)
	for _, m := range missed {
		t.Errorf("%s is not built for windows or linux, so the check never saw it: "+
			"remove its build constraint or extend the check", m)
	}
}
