// Package policy holds tests that enforce drivecat's hard rule: it never
// changes anything on the drives and shares it identifies or scans. The only
// thing drivecat writes is its own database, in internal/store.
package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// bannedOS are os functions that create, write, rename, delete or change
// files, plus the plain opens: source files must go through
// internal/readonly. Only internal/store may use them, for the database.
var bannedOS = set("Create", "CreateTemp", "OpenFile", "WriteFile", "Remove", "RemoveAll", "Rename",
	"Mkdir", "MkdirAll", "MkdirTemp", "Chmod", "Chtimes", "Chown", "Lchown", "Symlink", "Link",
	"Truncate", "Open", "ReadFile", "OpenRoot", "OpenInRoot", "CopyFS")

// bannedWindows are Windows APIs and constants that write, delete, rename,
// create or change files or volumes, in golang.org/x/sys/windows or syscall.
// No package may use them.
var bannedWindows = set(
	// access rights that allow changes
	"GENERIC_WRITE", "GENERIC_ALL", "FILE_WRITE_DATA", "FILE_APPEND_DATA", "FILE_WRITE_ATTRIBUTES",
	"FILE_WRITE_EA", "FILE_GENERIC_WRITE", "FILE_ALL_ACCESS", "DELETE", "WRITE_DAC", "WRITE_OWNER",
	// creation dispositions other than OPEN_EXISTING, and delete-on-close
	"CREATE_NEW", "CREATE_ALWAYS", "OPEN_ALWAYS", "TRUNCATE_EXISTING", "FILE_FLAG_DELETE_ON_CLOSE",
	// calls that change files or volumes
	"WriteFile", "WriteFileEx", "SetFileTime", "SetFileAttributes", "SetFileInformationByHandle",
	"SetEndOfFile", "SetFileValidData", "DeleteFile", "RemoveDirectory", "MoveFile", "MoveFileEx",
	"ReplaceFile", "CopyFile", "CreateDirectory", "CreateHardLink", "CreateSymbolicLink",
	"SetVolumeLabel", "SetVolumeMountPoint", "DeleteVolumeMountPoint", "FlushFileBuffers",
	"Ftruncate", "Fchmod", "Chmod", "Utimes", "UtimesNano", "Rename", "Unlink", "Rmdir", "Mkdir",
	"Symlink", "Link", "Open",
)

// Only internal/volume may call DeviceIoControl, and only through its
// allowlist (see ioctl.go); only these DLL functions may be loaded by name.
var (
	ioctlPackage    = "internal/volume"
	allowedDLLProcs = set("WNetGetConnectionW")
)

func TestNoWritesToSources(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		pkg := filepath.ToSlash(filepath.Dir(rel))

		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		checked++

		// The local names the file uses for the packages that matter.
		names := map[string]string{} // local name -> import path
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			local := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				local = imp.Name.Name
			}
			names[local] = p
		}

		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			at := fset.Position(sel.Pos())
			where := rel + ":" + strconv.Itoa(at.Line)

			switch names[x.Name] {
			case "os":
				if bannedOS[sel.Sel.Name] && pkg != "internal/store" {
					t.Errorf("%s: os.%s outside internal/store; read source files through internal/readonly",
						where, sel.Sel.Name)
				}
			case "golang.org/x/sys/windows", "syscall":
				name := sel.Sel.Name
				switch {
				case bannedWindows[name]:
					t.Errorf("%s: %s.%s can change files or volumes", where, x.Name, name)
				case name == "DeviceIoControl" && pkg != ioctlPackage:
					t.Errorf("%s: DeviceIoControl outside %s and its IOCTL allowlist", where, ioctlPackage)
				}
			}
			return true
		})

		// DLL functions loaded by name bypass the checks above.
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "NewProc" && sel.Sel.Name != "FindProc" && sel.Sel.Name != "MustFindProc") {
				return true
			}
			at := fset.Position(call.Pos())
			if len(call.Args) != 1 {
				t.Errorf("%s:%d: %s without a single literal name", rel, at.Line, sel.Sel.Name)
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			name, _ := strconv.Unquote(litValue(lit, ok))
			if !allowedDLLProcs[name] {
				t.Errorf("%s:%d: DLL function %q is not on the allowlist of read-only calls", rel, at.Line, name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 5 {
		t.Fatalf("only %d Go files checked under %s: is the walk broken?", checked, root)
	}
}

func litValue(lit *ast.BasicLit, ok bool) string {
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	return lit.Value
}

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}
