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
