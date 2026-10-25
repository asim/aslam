package arabiclearning

import "testing"

func TestCurriculum(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Sentences) != 12 || len(b.Roots) != 3 {
		t.Fatal("incomplete curriculum")
	}
	for _, word := range []string{"كِتَابٌ", "ٱلۡكِتَٰبُ", "كَاتِب", "مَكْتَبَة"} {
		if r := b.RootForWord(word); r == nil || r.Slug != "ktb" {
			t.Fatalf("missing root for %s", word)
		}
	}
	for _, word := range []string{"في", "كتاب آخر", "مكاتبة"} {
		if b.RootForWord(word) != nil {
			t.Fatalf("guessed root for %s", word)
		}
	}
	broken := Book{Sentences: []Sentence{{Slug: "test", Arabic: "a", English: "b", Words: []Word{{Root: "missing"}}}}}
	if broken.Validate() == nil {
		t.Fatal("accepted dangling root")
	}
}
