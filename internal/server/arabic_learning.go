package server

import (
	"aslam/db"
	"aslam/internal/arabiclearning"
	"fmt"
	"net/http"
	"strings"
)

func handleArabicLearning(w http.ResponseWriter, r *http.Request) {
	b, err := arabiclearning.Load()
	if err != nil {
		http.Error(w, "Lessons unavailable", 500)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/arabic/")
	parts := strings.Split(path, "/")
	if len(parts) > 2 || (parts[0] != "sentences" && parts[0] != "roots") {
		http.NotFound(w, r)
		return
	}
	d := map[string]interface{}{"Section": parts[0], "Title": "Sentences", "Roots": b.Roots, "Sentences": b.Sentences}
	if parts[0] == "roots" {
		d["Title"] = "Roots"
	}
	if len(parts) == 1 {
		p, t := db.GetReadingProgressContext(r.Context(), getUserID(r), "arabic")
		d["ContinuePath"], d["ContinueTitle"] = p, t
		renderTemplate(w, r, "arabic_learning_index.html", d)
		return
	}
	found := false
	if parts[0] == "sentences" {
		for i, s := range b.Sentences {
			if s.Slug != parts[1] {
				continue
			}
			found = true
			d["Sentence"], d["Title"] = s, s.Title
			d["Context"] = fmt.Sprintf("Arabic learning example (not a Quran quotation)\n%s\n%s\n%s\n%s", s.Arabic, s.Latin, s.English, s.Note)
			if i > 0 {
				d["Prev"] = "/arabic/sentences/" + b.Sentences[i-1].Slug
			}
			if i+1 < len(b.Sentences) {
				d["Next"] = "/arabic/sentences/" + b.Sentences[i+1].Slug
			}
		}
	} else {
		for i, root := range b.Roots {
			if root.Slug != parts[1] {
				continue
			}
			found = true
			d["Root"], d["Title"] = root, root.Title
			context := root.Arabic + " — " + root.Meaning
			for _, word := range root.Words {
				context += "\n" + word.Arabic + " (" + word.Latin + ") — " + word.Meaning + "; " + word.Pattern
			}
			d["Context"] = context
			var examples []arabiclearning.Sentence
			for _, slug := range root.Sentences {
				for _, s := range b.Sentences {
					if s.Slug == slug {
						examples = append(examples, s)
					}
				}
			}
			d["Examples"] = examples
			if i > 0 {
				d["Prev"] = "/arabic/roots/" + b.Roots[i-1].Slug
			}
			if i+1 < len(b.Roots) {
				d["Next"] = "/arabic/roots/" + b.Roots[i+1].Slug
			}
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	d["Path"] = r.URL.Path
	db.SaveReadingProgressContext(r.Context(), getUserID(r), "arabic", r.URL.Path, d["Title"].(string))
	renderTemplate(w, r, "arabic_learning.html", d)
}
