package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"
)

func sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// addSource records a source with files given as path -> content; content
// "!" stands for a file that could not be read.
func addSource(t *testing.T, s *Store, label string, files map[string]string) int64 {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	id, _, _, err := s.UpsertSource(ctx, SourceInfo{Kind: "disk", Fingerprint: "fp-" + label, Label: label}, now)
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := s.StartScan(ctx, id, "/", "X:\\", now)
	if err != nil {
		t.Fatal(err)
	}
	var rows []FileRow
	for p, c := range files {
		r := FileRow{RelPath: p, Size: int64(len(c)), MTime: Timestamp(now)}
		if c == "!" {
			r.Error = "Access is denied."
		} else {
			r.SHA256 = sum(c)
		}
		rows = append(rows, r)
	}
	if err := s.WriteFiles(ctx, id, scanID, now, rows); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestReport(t *testing.T) {
	s, _ := createTemp(t)
	ctx := context.Background()
	big := string(bytes.Repeat([]byte("v"), 1000))

	a := addSource(t, s, "A", map[string]string{
		"/photo1.jpg":      "photo-1",   // also on B
		"/photo2.jpg":      "photo-2xx", // only on A
		"/copy/photo2.jpg": "photo-2xx", // second copy inside A
		"/video.mp4":       big,         // also on B, twice
		"/empty.txt":       "",
		"/locked.vhdx":     "!",
	})
	b := addSource(t, s, "B", map[string]string{
		"/p1.jpg":  "photo-1",
		"/v1.mp4":  big,
		"/v2.mp4":  big,
		"/b.txt":   "only-b",
		"/e.txt":   "",
		"/ee.txt":  "",
		"/xx/y.md": "only-b-2",
	})

	r, err := s.Report(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Readable files: 5 on A, 7 on B. Unique content: photo-1, photo-2xx,
	// big, "", only-b, only-b-2.
	o := r.Overall
	if o.Files != 12 || o.Unreadable != 1 || o.UniqueFiles != 6 {
		t.Errorf("overall = %+v", o)
	}
	wantBytes := int64(7 + 9 + 9 + 1000 + 7 + 1000 + 1000 + 6 + 8)
	wantUnique := int64(7 + 9 + 1000 + 0 + 6 + 8)
	if o.Bytes != wantBytes || o.UniqueBytes != wantUnique {
		t.Errorf("bytes %d / unique %d, want %d / %d", o.Bytes, o.UniqueBytes, wantBytes, wantUnique)
	}

	byID := map[int64]SourceReport{}
	for _, sr := range r.Sources {
		byID[sr.ID] = sr
	}
	// Only on A: photo-2xx (counted once). The empty file is on B too.
	if sa := byID[a]; sa.OnlyHereFiles != 1 || sa.OnlyHereBytes != 9 || sa.Unreadable != 1 ||
		sa.Files != 5 || sa.UniqueFiles != 4 {
		t.Errorf("source A = %+v", sa)
	}
	if sb := byID[b]; sb.OnlyHereFiles != 2 || sb.OnlyHereBytes != 14 || sb.Files != 7 || sb.UniqueFiles != 5 {
		t.Errorf("source B = %+v", sb)
	}

	// Largest first: big has 3 copies (2000 spare bytes). Empty files are
	// never listed.
	if len(r.Duplicates) != 3 {
		t.Fatalf("duplicates = %+v", r.Duplicates)
	}
	g := r.Duplicates[0]
	if !bytes.Equal(g.SHA256, sum(big)) || g.Copies != 3 || g.Spare != 2000 || len(g.Places) != 3 ||
		g.Places[0] != "A: /video.mp4" {
		t.Errorf("largest group = %+v", g)
	}
	for _, d := range r.Duplicates {
		if d.Size == 0 {
			t.Errorf("empty files listed as duplicates: %+v", d)
		}
	}

	if r, err := s.Report(ctx, 0); err != nil || r.Duplicates != nil {
		t.Errorf("top 0: %v, %+v", err, r.Duplicates)
	}
}

func TestOtherSourceWith(t *testing.T) {
	s, _ := createTemp(t)
	ctx := context.Background()
	a := addSource(t, s, "A", map[string]string{"/x": "shared", "/y": "only-a"})
	b := addSource(t, s, "B", map[string]string{"/x": "shared"})

	if id, found, err := s.OtherSourceWith(ctx, sum("shared"), b); err != nil || !found || id != a {
		t.Errorf("shared from B: %d %v %v; want %d", id, found, err, a)
	}
	if _, found, err := s.OtherSourceWith(ctx, sum("only-a"), a); err != nil || found {
		t.Errorf("only-a from A: found %v, %v", found, err)
	}
}
