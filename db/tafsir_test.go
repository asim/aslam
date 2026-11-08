package db

import (
	"archive/zip"
	"aslam/data"
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestTafsirArchive(t *testing.T) {
	setupTestDB(t)
	if err := ImportTafsir(data.Tafsir); err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]int{"tafsir_passages": 1902, "tafsir_ayahs": 6236} {
		var n int
		if err := DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != want {
			t.Fatalf("%s: %d %v", table, n, err)
		}
	}
	ctx := context.Background()
	p, err := GetTafsir(ctx, 73, 4)
	if err != nil {
		t.Fatal(err)
	}
	if p.Ref != "73:1" || len(p.Ayahs) != 9 || p.Next == p.URL || p.Previous == p.URL {
		t.Fatalf("invalid shared passage: %+v", p)
	}
	p, err = GetTafsir(ctx, 1, 7)
	if err != nil || p.Ref != "1:6" {
		t.Fatalf("shared Fatihah: %v %v", p, err)
	}
	hits, err := SearchTafsir(ctx, "Allah", 3)
	if err != nil || len(hits) != 3 {
		t.Fatalf("search %v %v", hits, err)
	}
	if err := ImportTafsir(data.Tafsir); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, _ := z.Create("invalid.json")
	w.Write([]byte(`{"1:1":{"text":"changed"}}`))
	z.Close()
	if err := ImportTafsir(b.Bytes()); err == nil {
		t.Fatal("accepted incomplete archive")
	}
	p, err = GetTafsir(ctx, 1, 7)
	if err != nil || p.Ref != "1:6" {
		t.Fatal("failed import lost original", err)
	}
}
func TestTafsirSanitizer(t *testing.T) {
	clean, plain, err := SanitizeTafsir(`<h2 onclick="evil()">Heading</h2><script>evil()</script><p lang="ar" style="bad">الله</p><a href="javascript:evil()">Words</a>`)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"evil", "onclick", "javascript", "style="} {
		if strings.Contains(clean, bad) || strings.Contains(plain, bad) {
			t.Fatal(clean, plain)
		}
	}
	if !strings.Contains(clean, `dir="rtl"`) || !strings.Contains(plain, "الله") || !strings.Contains(plain, "Words") {
		t.Fatal(clean, plain)
	}
}
