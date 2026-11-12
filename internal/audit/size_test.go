package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestMeasureSize(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "1234567890")
	writeFile(t, dir, "node_modules/a/i.js", strings.Repeat("x", 3000))
	writeFile(t, dir, "node_modules/b/i.js", strings.Repeat("x", 2000))
	writeFile(t, dir, "src/app.go", "12345")
	writeFile(t, dir, "src/app.log", "123")
	writeFile(t, dir, "dist/out", "123456")
	writeFile(t, dir, ".dockerignore", "dist\n")
	findings, ig, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	fx, err := PlanFix(dir, findings, ig)
	if err != nil {
		t.Fatal(err)
	}
	sz, err := MeasureSize(dir, ig, fx)
	if err != nil {
		t.Fatal(err)
	}
	// Before: .dockerignore (5) + main.go (10) + node_modules (5000) + src (8).
	if sz.Before.Files != 6 || sz.Before.Bytes != 5023 {
		t.Errorf("before = %+v, want 6 files / 5023 bytes", sz.Before.Usage)
	}
	// After: node_modules and app.log are gone; the planned .dockerignore is
	// not written, so the file on disk still counts with its current size.
	if sz.After.Files != 3 || sz.After.Bytes != 20 {
		t.Errorf("after = %+v, want 3 files / 20 bytes", sz.After.Usage)
	}
	top := sz.topDirs()
	if len(top) != 2 || top[0].Path != "node_modules" || top[0].Files != 2 || top[0].Bytes != 5000 || top[1].Path != "src" {
		t.Errorf("top dirs = %+v", top)
	}

	var txt bytes.Buffer
	WriteText(&txt, findings, ig, sz)
	for _, sub := range []string{
		"Build context: 5.0 kB in 6 files now, 20 B in 3 files with the suggested patterns.",
		"5.0 kB  node_modules/ (2 files)",
	} {
		if !strings.Contains(txt.String(), sub) {
			t.Errorf("text missing %q:\n%s", sub, txt.String())
		}
	}

	var js bytes.Buffer
	WriteJSON(&js, findings, ig, sz)
	var rep struct {
		Size struct {
			Before  Usage `json:"before"`
			After   Usage `json:"after"`
			TopDirs []struct {
				Path  string `json:"path"`
				Files int    `json:"files"`
				Bytes int64  `json:"bytes"`
			} `json:"top_dirs"`
		} `json:"size"`
	}
	if err := json.Unmarshal(js.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Size.Before.Bytes != 5023 || rep.Size.After.Files != 3 || len(rep.Size.TopDirs) != 2 || rep.Size.TopDirs[0].Path != "node_modules/" {
		t.Errorf("unexpected size JSON: %s", js.String())
	}
}

func TestTopDirsLimit(t *testing.T) {
	dir := t.TempDir()
	for i := range 12 {
		writeFile(t, dir, fmt.Sprintf("d%02d/f", i), strings.Repeat("x", i+1))
	}
	cu, err := MeasureContext(dir, &Ignore{})
	if err != nil {
		t.Fatal(err)
	}
	sz := &SizeReport{Before: cu, After: cu}
	top := sz.topDirs()
	if len(top) != TopDirs || top[0].Path != "d11" || top[TopDirs-1].Path != "d02" {
		t.Errorf("want the %d largest directories, largest first, got %+v", TopDirs, top)
	}
}
