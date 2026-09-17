// Package seerah contains the page-preserving Sealed Nectar reader dataset.
package seerah

import (
	"archive/zip"
	"aslam/data"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

var source = data.Seerah

type Block struct {
	Text    string
	Heading bool
	ID      string
}
type Chapter struct {
	Title string
	Page  int
}
type Page struct {
	Number  int
	Chapter int
	Blocks  []Block
}
type Book struct {
	Title      string
	Author     string
	Translator string
	Chapters   []Chapter
	Pages      []Page
}

func Load() (*Book, error) {
	var b Book
	archive, err := zip.NewReader(bytes.NewReader(source), int64(len(source)))
	if err != nil {
		return nil, err
	}
	r, err := archive.Open("seerah.json")
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return nil, err
	}
	if len(b.Pages) != 316 || len(b.Chapters) == 0 {
		return nil, fmt.Errorf("incomplete seerah dataset")
	}
	for i, p := range b.Pages {
		if p.Number != i+8 || p.Chapter < 0 || p.Chapter >= len(b.Chapters) || len(p.Blocks) == 0 {
			return nil, fmt.Errorf("invalid seerah page %d", p.Number)
		}
	}
	return &b, nil
}

func Version() string { return fmt.Sprintf("%x", sha256.Sum256(source)) }
func (b *Book) Page(number int) (Page, bool) {
	if number < 8 || number > 323 {
		return Page{}, false
	}
	return b.Pages[number-8], true
}
func (p Page) Text() string {
	var parts []string
	for _, block := range p.Blocks {
		parts = append(parts, block.Text)
	}
	return strings.Join(parts, "\n\n")
}
