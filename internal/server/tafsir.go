package server

import (
	"aslam/db"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

func handleTafsir(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", 405)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) > 1 && parts[1] != db.TafsirEdition {
		http.NotFound(w, r)
		return
	}
	chapters, err := quranChapters()
	if err != nil {
		http.Error(w, "Chapters unavailable", 503)
		return
	}
	path, title := db.GetReadingProgressContext(r.Context(), getUserID(r), "tafsir")
	view := map[string]interface{}{"Source": db.TafsirSource, "SourceURL": db.TafsirSourceURL, "ContinuePath": path, "ContinueTitle": title, "Chapters": chapters}
	if len(parts) <= 2 {
		renderTemplate(w, r, "tafsir_index.html", view)
		return
	}
	ch, err := strconv.Atoi(parts[2])
	if err != nil || ch < 1 || ch > 114 {
		http.NotFound(w, r)
		return
	}
	view["Chapter"] = ch
	view["ChapterName"] = chapters[ch-1]["Name"]
	if len(parts) == 3 {
		offset, limit, err := apiPage(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		items, err := db.BrowseKnowledge(r.Context(), "tafsir", strconv.Itoa(ch), "", offset, limit+1)
		if err != nil {
			http.Error(w, "Tafsir unavailable", 503)
			return
		}
		if len(items) > limit {
			items = items[:limit]
			view["Next"] = fmt.Sprintf("/tafsir/ibn-kathir/%d?offset=%d&limit=%d", ch, offset+limit, limit)
		}
		if offset > 0 {
			view["Previous"] = fmt.Sprintf("/tafsir/ibn-kathir/%d?offset=%d&limit=%d", ch, max(0, offset-limit), limit)
		}
		view["Passages"] = items
		renderTemplate(w, r, "tafsir_index.html", view)
		return
	}
	if len(parts) != 4 {
		http.NotFound(w, r)
		return
	}
	verse, err := strconv.Atoi(parts[3])
	if err != nil || verse < 1 {
		http.NotFound(w, r)
		return
	}
	passage, err := db.GetTafsir(r.Context(), ch, verse)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Tafsir unavailable", 503)
		return
	}
	// Shared verses have one canonical passage URL, avoiding duplicate reading stops.
	if r.URL.Path != passage.URL {
		http.Redirect(w, r, passage.URL, 302)
		return
	}
	db.SaveReadingProgressContext(r.Context(), getUserID(r), "tafsir", passage.URL, passage.Title)
	view["Passage"] = passage
	view["HTML"] = template.HTML(passage.HTML)
	view["ChatContext"] = passage.Title + " (" + passage.URL + "). Source: " + passage.Source + ". Commentary excerpt:\n\n" + truncateRunes(passage.Text, 8000)
	links := []map[string]string{}
	for _, ref := range passage.Ayahs {
		links = append(links, map[string]string{"Ref": ref, "URL": "/quran/" + strings.ReplaceAll(ref, ":", "/")})
	}
	view["Ayahs"] = links
	renderTemplate(w, r, "tafsir.html", view)
}
