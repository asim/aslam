package server

import (
	"archive/zip"
	"aslam/data"
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"strings"
	"testing"
)

func TestIslamQAParagraphs(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"wrapped", "Praise be to Allah.\nFirstly:\n\nThe cross is one \n\tof the symbols.\n\nNext paragraph.", "<p>Praise be to Allah.</p><p>Firstly:</p><p>The cross is one of the symbols.</p><p>Next paragraph.</p>"},
		{"modern", "First paragraph.\nSecond paragraph.", "<p>First paragraph.</p><p>Second paragraph.</p>"},
		{"numbered", "Introduction:\n\n1.\n\tFirst item with \n\ta continuation.\n2. Second item.", "<p>Introduction:</p><p>1. First item with a continuation.</p><p>2. Second item.</p>"},
		{"escape", "<script>alert(1)</script>\r\n \t\r\nText & more", "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p><p>Text &amp; more</p>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(islamQAParagraphs(tc.input)); got != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}

func TestIslamQAModernArchiveParagraphs(t *testing.T) {
	z, err := zip.NewReader(bytes.NewReader(data.IslamQA), int64(len(data.IslamQA)))
	if err != nil {
		t.Fatal(err)
	}
	f, err := z.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	var entries []struct{ Question, Answer string }
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range entries {
		if e.Question != "What Is the Sound `Aqidah?" && !strings.HasPrefix(e.Question, "Are ahaad hadiths probably sound") {
			continue
		}
		found++
		rendered := string(islamQAParagraphs(e.Answer))
		for _, line := range strings.Split(e.Answer, "\n") {
			line = strings.Join(strings.Fields(line), " ")
			if line != "" && !strings.Contains(rendered, "<p>"+template.HTMLEscapeString(line)+"</p>") {
				t.Fatalf("%s: lost paragraph %q", e.Question, line)
			}
		}
	}
	if found != 2 {
		t.Fatalf("found %d archive fixtures", found)
	}
}
