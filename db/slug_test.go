package db

import (
	"strings"
	"testing"
)

func TestSlugDeterministic(t *testing.T) {
	a := Slug("Can Babies See the Angels?", "Can Babies See the Angels?|Praise be to Allah...")
	b := Slug("Can Babies See the Angels?", "Can Babies See the Angels?|Praise be to Allah...")
	if a != b {
		t.Fatalf("Slug not deterministic: %q vs %q", a, b)
	}
}

func TestSlugDifferentContent(t *testing.T) {
	a := Slug("Conditions of righteous deeds", "Conditions of righteous deeds|first answer")
	b := Slug("Conditions of righteous deeds", "Conditions of righteous deeds|second answer")
	if a == b {
		t.Fatalf("Same title with different content produced identical slug: %q", a)
	}
}

func TestSlugFormat(t *testing.T) {
	s := Slug("Hello, World! (test)", "anything")
	prefix := "hello-world-test-"
	if !strings.HasPrefix(s, prefix) {
		t.Fatalf("expected prefix %q, got %q", prefix, s)
	}
	parts := strings.Split(s, "-")
	suffix := parts[len(parts)-1]
	if len(suffix) != 6 {
		t.Fatalf("expected 6-char hex suffix, got %q", suffix)
	}
}

func TestSlugEmptyTitle(t *testing.T) {
	s := Slug("", "some content")
	if !strings.HasPrefix(s, "item-") {
		t.Fatalf("expected empty title to fall back to 'item-', got %q", s)
	}
}

func TestSlugLongTitle(t *testing.T) {
	long := strings.Repeat("abcdefghij", 20)
	s := Slug(long, "x")
	base := strings.TrimSuffix(s, "-"+strings.Split(s, "-")[len(strings.Split(s, "-"))-1])
	if len(base) > 60 {
		t.Fatalf("base too long: %d chars in %q", len(base), s)
	}
}

func TestSlugUnicodeStripped(t *testing.T) {
	s := Slug("صلاة Prayer", "x")
	if !strings.HasPrefix(s, "prayer-") {
		t.Fatalf("expected non-ascii chars to be stripped, got %q", s)
	}
}
