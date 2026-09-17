package server

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"time"
)

func TestSearchRendersUndatedSourcesAndFullSnippets(t *testing.T) {
	funcs := template.FuncMap{
		"formatTime": func(v time.Time) string { return v.Format("2006-01-02") },
		"truncate": func(s string, n int) string {
			if len(s) > n {
				return s[:n]
			}
			return s
		},
	}
	tpl, err := template.New("").Funcs(funcs).Parse(`{{define "style"}}{{end}}{{define "header"}}{{end}}`)
	if err != nil {
		t.Fatal(err)
	}
	tpl, err = tpl.ParseFiles("html/search.html")
	if err != nil {
		t.Fatal(err)
	}
	snippet := strings.Repeat("context ", 30) + "originated <script>alert(1)</script>"
	data := map[string]interface{}{"Query": "originated", "Results": []map[string]interface{}{
		{"Kind": "seerah", "URL": "/seerah/page/8", "Title": "Seerah page 8", "Content": snippet, "Role": "The Sealed Nectar"},
		{"Kind": "chat", "URL": "/chat/1", "Title": "Later result", "Content": "text", "Role": "user", "CreatedAt": time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)},
	}}
	var out bytes.Buffer
	if err := tpl.ExecuteTemplate(&out, "search.html", data); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Later result", "2026-09-14", "originated &lt;script&gt;alert(1)&lt;/script&gt;", "</html>"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}
