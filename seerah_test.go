package main

import (
	"aslam/seerah"
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSeerahReaderNavigation(t *testing.T) {
	var err error
	seerahBook, err = seerah.Load()
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err = template.New("").Parse(`{{define "style"}}{{end}}{{define "header"}}{{end}}`)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err = tmpl.ParseFiles("html/seerah.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"8", "44", "323"} {
		w := httptest.NewRecorder()
		handleSeerahPage(w, httptest.NewRequest("GET", "/seerah/page/"+n, nil))
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, "PDF page "+n) {
			t.Fatalf("page %s: %d %s", n, w.Code, body)
		}
		if strings.Contains(body, `href="/seerah/page/7"`) || strings.Contains(body, `href="/seerah/page/324"`) {
			t.Fatal("navigation outside book")
		}
	}
	for _, path := range []string{"/seerah/page/7", "/seerah/page/324", "/seerah/page/nope", "/seerah/page/8?section=unknown"} {
		w := httptest.NewRecorder()
		handleSeerahPage(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	handleSeerahPage(w, httptest.NewRequest("GET", "/seerah/page/8?section=block-1", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `id="block-1"`) {
		t.Fatal("section target absent")
	}
}
