// Package arabiclearning provides a small, explicit curriculum alongside Quranic vocabulary.
package arabiclearning

import (
	"archive/zip"
	"aslam/data"
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"unicode"
)

type Word struct{ Arabic, Latin, Meaning, Pattern, Root string }
type Sentence struct {
	Slug, Title, Level, Arabic, Latin, English, Note string
	Words                                            []Word
}
type Root struct {
	Slug, Title, Arabic, Meaning string
	Words                        []Word
	Sentences, Forms             []string
}
type Book struct {
	Roots     []Root
	Sentences []Sentence
}

var once sync.Once
var book Book
var loadErr error

func Load() (*Book, error) {
	once.Do(func() {
		z, err := zip.NewReader(bytes.NewReader(data.ArabicLearning), int64(len(data.ArabicLearning)))
		if err != nil {
			loadErr = err
			return
		}
		f, err := z.Open("lessons.json")
		if err != nil {
			loadErr = err
			return
		}
		defer f.Close()
		loadErr = json.NewDecoder(f).Decode(&book)
		if loadErr == nil {
			loadErr = book.Validate()
		}
	})
	return &book, loadErr
}
func (b *Book) Validate() error {
	roots := map[string]bool{}
	sentences := map[string]bool{}
	for _, r := range b.Roots {
		if r.Slug == "" || roots[r.Slug] || len(r.Words) == 0 {
			return fmt.Errorf("invalid root %q", r.Slug)
		}
		roots[r.Slug] = true
	}
	for _, s := range b.Sentences {
		if s.Slug == "" || sentences[s.Slug] || len(s.Words) == 0 || s.Arabic == "" || s.English == "" {
			return fmt.Errorf("invalid sentence %q", s.Slug)
		}
		sentences[s.Slug] = true
		for _, w := range s.Words {
			if w.Root != "" && !roots[w.Root] {
				return fmt.Errorf("unknown root %q", w.Root)
			}
		}
	}
	for _, r := range b.Roots {
		for _, s := range r.Sentences {
			if !sentences[s] {
				return fmt.Errorf("unknown sentence %q", s)
			}
		}
	}
	return nil
}

// Normalize removes vocalization and Quranic annotation marks, not word prefixes.
func Normalize(s string) string {
	var out []rune
	for _, r := range s {
		if r == 'ٰ' {
			out = append(out, 'ا')
			continue
		}
		if unicode.Is(unicode.Mn, r) || r == 'ـ' {
			continue
		}
		if r == 'ٱ' {
			r = 'ا'
		}
		out = append(out, r)
	}
	return string(out)
}
func (b *Book) RootForWord(word string) *Root {
	word = Normalize(word)
	for i := range b.Roots {
		for _, form := range b.Roots[i].Forms {
			if word == form {
				return &b.Roots[i]
			}
		}
	}
	return nil
}
