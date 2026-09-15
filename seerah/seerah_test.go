package seerah

import (
	"strings"
	"testing"
)

func TestDatasetPagesAndAnchors(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{-1, 0, 7, 324, 999} {
		if _, ok := b.Page(n); ok {
			t.Fatalf("accepted page %d", n)
		}
	}
	for _, p := range b.Pages {
		got, ok := b.Page(p.Number)
		if !ok || got.Number != p.Number {
			t.Fatal("page lookup mismatch")
		}
		ids := map[string]bool{}
		for _, block := range p.Blocks {
			if block.ID == "" || ids[block.ID] || strings.TrimSpace(block.Text) == "" {
				t.Fatalf("invalid block on page %d", p.Number)
			}
			ids[block.ID] = true
			if strings.Contains(block.Text, "MSA NIU") || strings.Contains(block.Text, "Win2PDF") {
				t.Fatal("page furniture retained")
			}
		}
	}
	for i, ch := range b.Chapters {
		p, ok := b.Page(ch.Page)
		if !ok || p.Chapter != i {
			t.Fatalf("bad chapter target %s", ch.Title)
		}
	}
	p, _ := b.Page(44)
	if !strings.Contains(p.Text(), "[Rahmat Al-lil'alameen 1/47; Ibn Hisham 1/235,236; Fi Zilal Al-Qur'an 29/166]") {
		t.Fatal("reference not retained")
	}
}

func TestReviewedNameCorrections(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range b.Pages {
		for _, damaged := range []string{"All?", "Qur’?", "Muhsin?", "Allah ’s", "Allah ,", "Qur’an ic", "Allah u Akbar"} {
			if strings.Contains(p.Text(), damaged) {
				t.Fatalf("page %d contains %q", p.Number, damaged)
			}
		}
	}
	for page, want := range map[int]string{10: "Allah’s", 22: "Qur’anic verses", 71: "Allahu Akbar"} {
		p, _ := b.Page(page)
		if !strings.Contains(p.Text(), want) {
			t.Fatalf("page %d missing %q", page, want)
		}
	}
	p, _ := b.Page(10)
	if !strings.Contains(p.Text(), "reward the Muhsinûn (good-doers,") {
		t.Fatal("confirmed Muhsinûn correction missing")
	}
	p, _ = b.Page(68)
	if !strings.Contains(p.Text(), "My Lord is Allah?") {
		t.Fatal("genuine question after damaged name lost")
	}
	p, _ = b.Page(9)
	if !strings.Contains(p.Text(), "‘Imran bin ‘Amr Muzaiqbâ’") {
		t.Fatal("scan-verified name missing")
	}
	p, _ = b.Page(46)
	if !strings.HasSuffix(p.Blocks[2].Text, "Moses عليه السلام") ||
		!strings.HasPrefix(p.Blocks[3].Text, "and clearly attested") ||
		p.Blocks[2].ID != "block-3" || p.Blocks[3].ID != "block-4" {
		t.Fatal("cross-block honorific or its anchors incorrect")
	}
}

func TestQuestionMarkCorrectionPassComplete(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	questions := 0
	for _, p := range b.Pages {
		questions += strings.Count(p.Text(), "?")
		if strings.Contains(p.Text(), "#146;") || strings.Contains(p.Text(), "/i>") {
			t.Fatalf("damaged markup remains on page %d", p.Number)
		}
	}
	if questions != 180 {
		t.Fatalf("expected 180 retained genuine questions, got %d", questions)
	}
	p, _ := b.Page(12)
	if strings.Count(p.Text(), "Taimâ’") != 3 {
		t.Fatal("not all three place-name occurrences corrected")
	}
}
