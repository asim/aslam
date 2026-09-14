package main

import (
	"aslam/db"
	"aslam/seerah"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

var seerahBook *seerah.Book

func handleSeerahIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/seerah" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", 405)
		return
	}
	path, title := db.GetReadingProgress(getUserID(r), "seerah")
	renderTemplate(w, r, "seerah_index.html", map[string]interface{}{"Book": seerahBook, "ContinuePath": path, "ContinueTitle": title})
}

func handleSeerahPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", 405)
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/seerah/page/")
	number, err := strconv.Atoi(raw)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	page, ok := seerahBook.Page(number)
	if !ok {
		http.NotFound(w, r)
		return
	}
	path := fmt.Sprintf("/seerah/page/%d", number)
	if raw != strconv.Itoa(number) {
		http.Redirect(w, r, path, http.StatusMovedPermanently)
		return
	}
	section := r.URL.Query().Get("section")
	if section != "" {
		found := false
		for _, block := range page.Blocks {
			if block.ID == section && block.Heading {
				found = true
			}
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		path += "?section=" + section + "#" + section
	}
	title := fmt.Sprintf("%s — page %d", seerahBook.Chapters[page.Chapter].Title, number)
	db.SaveReadingProgress(getUserID(r), "seerah", path, title)
	previous, next := 0, 0
	if number > 8 {
		previous = number - 1
	}
	if number < 323 {
		next = number + 1
	}
	previousChapter, nextChapter := 0, 0
	if page.Chapter > 0 {
		previousChapter = seerahBook.Chapters[page.Chapter-1].Page
	}
	if page.Chapter+1 < len(seerahBook.Chapters) {
		nextChapter = seerahBook.Chapters[page.Chapter+1].Page
	}
	renderTemplate(w, r, "seerah.html", map[string]interface{}{"Book": seerahBook, "Page": page, "Title": title, "Content": page.Text(), "Path": path, "Previous": previous, "Next": next, "PreviousChapter": previousChapter, "NextChapter": nextChapter})
}
