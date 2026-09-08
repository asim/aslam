package db

import (
	"archive/zip"
	"encoding/json"
	"strings"
	"testing"
)

func TestReviewedGhazaliCorrections(t *testing.T) {
	z, err := zip.OpenReader("../data/ghazali.zip")
	if err != nil { t.Fatal(err) }
	defer z.Close()
	var entries []struct {
		Volume int
		Chapter string
		Part int
		Content string
	}
	for _, f := range z.File {
		if f.Name != "ghazali.json" { continue }
		r, err := f.Open()
		if err != nil { t.Fatal(err) }
		err = json.NewDecoder(r).Decode(&entries)
		r.Close()
		if err != nil { t.Fatal(err) }
	}
	if len(entries) == 0 { t.Fatal("missing fixture") }
	changed := 0
	for _, e := range entries {
		got := correctGhazaliText(e.Volume, e.Chapter, e.Part, e.Content)
		if got != e.Content { changed++ }
		if twice := correctGhazaliText(e.Volume, e.Chapter, e.Part, got); twice != got {
			t.Fatalf("correction not idempotent: %s part %d", e.Chapter, e.Part)
		}
		if e.Volume != 1 || e.Chapter != "Chapter I: Acquisition of Knowledge" { continue }
		if e.Part == 1 {
			for _, want := range []string{"difference between", "would have known it", "are very high", "58:11", "29:43", "4:83", "7:26", "7:7", "29:49", "55:3–4", "PROOF OF THE QURAN\n\n", "HADIS\n\n"} {
				if !strings.Contains(got, want) { t.Errorf("missing %q", want) }
			}
			if strings.Contains(got, "Vol-I KNOWLEDGE 19") || strings.HasSuffix(got, " He") {
				t.Error("printed page boundary retained")
			}
		}
		if e.Part == 2 && !strings.HasPrefix(got, "He said: The learned are the heirs") {
			t.Error("continuation not repaired")
		}
	}
	if changed != 2 { t.Fatalf("changed %d sections, want 2", changed) }
}
