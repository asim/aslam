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

func TestGhazaliUnrelatedReferencesPreserved(t *testing.T) {
	const chapter = "Chapter I: Acquisition of Knowledge"
	// The same numbers may legitimately refer to other quotations in this part.
	const unrelated = "Other quotation - 58 : 12. Other quotation - 29 : 42. Other quotation - 4 : 93. Other quotation - 7 : 25. Other quotation -7:6. Other quotation - 29 : 48. Other quotation - 55 ; 2."
	const want = "Other quotation - 58:12. Other quotation - 29:42. Other quotation - 4:93. Other quotation - 7:25. Other quotation -7:6. Other quotation - 29:48. Other quotation - 55 ; 2."
	if got := correctGhazaliText(1, chapter, 1, unrelated); got != want {
		t.Fatalf("unrelated citation changed: %q", got)
	}
	cases := [][2]string{
		{"God says: Those who are believers among you and the learned, God will increase their rank - 58 : 12.", "God says: Those who are believers among you and the learned, God will increase their rank - 58:11."},
		{"God says: These parables We set forth for men and none understands them except the learned - 29 : 42.", "God says: These parables We set forth for men and none understands them except the learned - 29:43."},
		{"God says: If they had only referred it to the Apostle and to those charged with authority among them, those of them who would investigate it would have know it - 4 : 93.", "God says: If they had only referred it to the Apostle and to those charged with authority among them, those of them who would investigate it would have known it - 4:83."},
		{"God says: O the children of Adam! I have sent down to you raiment to cover your shame and adornment to you, but the raiment of piety is best - 7 : 25.", "God says: O the children of Adam! I have sent down to you raiment to cover your shame and adornment to you, but the raiment of piety is best - 7:26."},
		{"God says: I shall recount their story with knowledge -7:6.", "God says: I shall recount their story with knowledge - 7:7."},
		{"God says: It is a clear sign in the hearts of those to whom knowledge has reached - 29 : 48.", "God says: It is a clear sign in the hearts of those to whom knowledge has reached - 29:49."},
		{"God says: He created man and taught him to speak - 55 ; 2.", "God says: He created man and taught him to speak - 55:3–4."},
	}
	for _, tc := range cases {
		got := correctGhazaliText(1, chapter, 1, tc[0] + "\n\n" + unrelated)
		if got != tc[1] + "\n\n" + want {
			t.Errorf("quotation correction affected unrelated references: %q", got)
		}
		for _, scope := range [][2]int{{2, 1}, {1, 3}} {
			if got := correctGhazaliText(scope[0], chapter, scope[1], tc[0]); got != tc[0] {
				t.Error("reference changed outside reviewed section")
			}
		}
	}
}
