package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"aslam/db"
)

func handleAdhkarIndex(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	data := map[string]interface{}{}

	categories, _ := db.GetAdhkarCategories()
	data["Categories"] = categories

	if category != "" {
		items, _ := db.GetAdhkarByCategory(category)
		data["Items"] = items
		data["SelectedCategory"] = category
	} else {
		items, _ := db.GetAllAdhkar()
		data["Items"] = items
	}

	p, t := db.GetReadingProgress(getUserID(r), "adhkar")
	data["ContinuePath"] = p
	data["ContinueTitle"] = t

	renderTemplate(w, r, "adhkar_index.html", data)
}

func handleAdhkarView(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/adhkar/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetAdhkar(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, next := db.GetAdhkarPrevNext(slug)
	item["PrevSlug"] = prev
	item["NextSlug"] = next
	db.SaveReadingProgress(getUserID(r), "adhkar", r.URL.Path, item["Title"].(string))
	renderTemplate(w, r, "adhkar.html", item)
}

func handleRiyadIndex(w http.ResponseWriter, r *http.Request) {
	book := r.URL.Query().Get("book")
	data := map[string]interface{}{}

	books, _ := db.GetRiyadBooks()
	data["Books"] = books

	if book != "" {
		items, _ := db.GetRiyadByBook(book)
		data["Items"] = items
		data["SelectedBook"] = book
	}

	p, t := db.GetReadingProgress(getUserID(r), "salihin")
	data["ContinuePath"] = p
	data["ContinueTitle"] = t

	renderTemplate(w, r, "salihin_index.html", data)
}

func handleRiyadView(w http.ResponseWriter, r *http.Request) {
	numStr := strings.TrimPrefix(r.URL.Path, "/salihin/")
	number, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetRiyad(number)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, next := db.GetRiyadPrevNext(number)
	item["PrevNumber"] = prev
	item["NextNumber"] = next
	db.SaveReadingProgress(getUserID(r), "salihin", r.URL.Path, fmt.Sprintf("Hadith %d", number))
	renderTemplate(w, r, "salihin.html", item)
}

func handleStoriesIndex(w http.ResponseWriter, r *http.Request) {
	prophets, _ := db.GetAllProphets()
	p, t := db.GetReadingProgress(getUserID(r), "stories")
	renderTemplate(w, r, "stories_index.html", map[string]interface{}{
		"Prophets":      prophets,
		"ContinuePath":  p,
		"ContinueTitle": t,
	})
}

func handleStoriesView(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/stories/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	prophet, err := db.GetProphet(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Parse sections JSON
	var rawSections []struct {
		Narrative string `json:"narrative"`
		Verses    []struct {
			Ref     string `json:"ref"`
			Chapter int    `json:"chapter"`
			Start   int    `json:"start"`
			End     int    `json:"end"`
			Context string `json:"context"`
		} `json:"verses"`
	}
	sectionsJSON, _ := prophet["VersesJSON"].(string)
	json.Unmarshal([]byte(sectionsJSON), &rawSections)

	type VerseGroup struct {
		Ref     string
		Context string
		Verses  []map[string]interface{}
	}
	type StorySection struct {
		Narrative template.HTML
		Groups    []VerseGroup
	}
	var sections []StorySection
	for _, rs := range rawSections {
		var groups []VerseGroup
		for _, vr := range rs.Verses {
			verses, _ := db.GetQuranVerseRange(vr.Chapter, vr.Start, vr.End)
			groups = append(groups, VerseGroup{
				Ref:     vr.Ref,
				Context: vr.Context,
				Verses:  verses,
			})
		}
		narrative := strings.ReplaceAll(rs.Narrative, "\n\n", "</p><p>")
		narrative = "<p>" + narrative + "</p>"
		sections = append(sections, StorySection{
			Narrative: template.HTML(narrative),
			Groups:    groups,
		})
	}
	prophet["Sections"] = sections

	prev, next := db.GetProphetPrevNext(slug)
	prophet["PrevSlug"] = prev
	prophet["NextSlug"] = next

	db.SaveReadingProgress(getUserID(r), "stories", r.URL.Path, prophet["Name"].(string))
	renderTemplate(w, r, "stories.html", prophet)
}

func handleArabicIndex(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	level := r.URL.Query().Get("level")
	data := map[string]interface{}{}

	// Levels: each is 50 words by frequency
	levels := []map[string]interface{}{
		{"Level": 1, "Label": "Essential (1-50)", "Desc": "The 50 most frequent words — covers ~25% of the Quran"},
		{"Level": 2, "Label": "Core (51-100)", "Desc": "The next 50 most common words"},
		{"Level": 3, "Label": "Common (101-200)", "Desc": "100 more frequently used words"},
		{"Level": 4, "Label": "Intermediate (201-500)", "Desc": "300 words to deepen your vocabulary"},
		{"Level": 5, "Label": "Advanced (501-1000)", "Desc": "500 words for strong comprehension"},
	}
	data["Levels"] = levels

	if query != "" {
		results, _ := db.SearchArabic(query)
		data["Words"] = results
		data["Query"] = query
	} else if level != "" {
		lvl, _ := strconv.Atoi(level)
		var offset, limit int
		switch lvl {
		case 1:
			offset, limit = 0, 50
		case 2:
			offset, limit = 50, 50
		case 3:
			offset, limit = 100, 100
		case 4:
			offset, limit = 200, 300
		case 5:
			offset, limit = 500, 500
		default:
			offset, limit = 0, 50
			lvl = 1
		}
		words, _ := db.GetArabicByFrequencyRange(offset, limit)
		data["Words"] = words
		data["SelectedLevel"] = lvl
	} else {
		words, _ := db.GetArabicByFrequency(50)
		data["Words"] = words
		data["SelectedLevel"] = 1
	}

	p, t := db.GetReadingProgress(getUserID(r), "arabic")
	data["ContinuePath"] = p
	data["ContinueTitle"] = t

	renderTemplate(w, r, "arabic_index.html", data)
}

func handleArabicView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/arabic/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetArabicWord(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prevID, nextID := db.GetArabicPrevNext(id)
	item["PrevID"] = prevID
	item["NextID"] = nextID

	// Parse example_ref like "Al-Fatihah 1:1" to fetch the verse
	if ref, ok := item["ExampleRef"].(string); ok && ref != "" {
		if m := regexp.MustCompile(`(\d+):(\d+)$`).FindStringSubmatch(ref); m != nil {
			ch, _ := strconv.Atoi(m[1])
			v, _ := strconv.Atoi(m[2])
			if verse, err := db.GetQuranVerse(ch, v); err == nil {
				item["Verse"] = verse
				item["VerseURL"] = fmt.Sprintf("/quran/%d/%d", ch, v)
				item["VerseWBW"] = fmt.Sprintf("https://reminder.dev/quran/%d?wbw=1#%d", ch, v)
			}
		}
	}

	translit, _ := item["Transliteration"].(string)
	db.SaveReadingProgress(getUserID(r), "arabic", r.URL.Path, translit)
	renderTemplate(w, r, "arabic.html", item)
}

func handleArabicSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"results": []interface{}{}})
		return
	}

	results, err := db.SearchArabic(query)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if results == nil {
		results = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
}

func handleQuranIndex(w http.ResponseWriter, r *http.Request) {
	chapters, _ := db.GetQuranChapters()
	p, t := db.GetReadingProgress(getUserID(r), "quran")
	renderTemplate(w, r, "quran_index.html", map[string]interface{}{
		"Chapters":      chapters,
		"ContinuePath":  p,
		"ContinueTitle": t,
	})
}

func handleQuranRouter(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/quran/")
	if strings.Contains(path, "/") {
		handleQuranView(w, r)
		return
	}
	chapter, err := strconv.Atoi(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	verses, _ := db.GetQuranChapter(chapter)
	if len(verses) == 0 {
		http.NotFound(w, r)
		return
	}
	first, _ := db.GetQuranVerse(chapter, 1)
	name := ""
	if first != nil {
		if n, ok := first["ChapterName"].(string); ok {
			name = n
		}
	}
	prevCh, nextCh := 0, 0
	if chapter > 1 {
		prevCh = chapter - 1
	}
	if chapter < 114 {
		nextCh = chapter + 1
	}
	renderTemplate(w, r, "quran_chapter.html", map[string]interface{}{
		"Chapter":     chapter,
		"ChapterName": name,
		"Verses":      verses,
		"PrevChapter": prevCh,
		"NextChapter": nextCh,
	})
}

func handleHadithIndex(w http.ResponseWriter, r *http.Request) {
	books, _ := db.GetHadithBooks()
	renderTemplate(w, r, "hadith_index.html", map[string]interface{}{"Books": books})
}

func handleHadithRouter(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/hadith/")
	if strings.HasPrefix(path, "book/") {
		bookStr := strings.TrimPrefix(path, "book/")
		bookNum, err := strconv.ParseInt(bookStr, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		items, _ := db.GetHadithByBook(bookNum)
		if len(items) == 0 {
			http.NotFound(w, r)
			return
		}
		books, _ := db.GetHadithBooks()
		bookName := ""
		for _, b := range books {
			if b["BookNumber"] == bookNum {
				bookName, _ = b["Book"].(string)
				break
			}
		}
		prevBook, nextBook := db.GetHadithBookPrevNext(bookNum)
		renderTemplate(w, r, "hadith_book.html", map[string]interface{}{
			"BookNumber": bookNum,
			"BookName":   bookName,
			"Items":      items,
			"PrevBook":   prevBook,
			"NextBook":   nextBook,
		})
		return
	}
	handleHadithView(w, r)
}

func handleNamesIndex(w http.ResponseWriter, r *http.Request) {
	names, _ := db.GetAllNames()
	renderTemplate(w, r, "names_index.html", map[string]interface{}{"Names": names})
}

func handleQuranView(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/quran/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	chapter, err := strconv.Atoi(parts[0])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	verse, err := strconv.Atoi(parts[1])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetQuranVerse(chapter, verse)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	chName, _ := item["ChapterName"].(string)
	db.SaveReadingProgress(getUserID(r), "quran", r.URL.Path, fmt.Sprintf("%s %d:%d", chName, chapter, verse))

	prevCh, prevV, nextCh, nextV := db.GetQuranVersePrevNext(chapter, verse)
	if prevCh > 0 {
		item["PrevURL"] = fmt.Sprintf("/quran/%d/%d", prevCh, prevV)
	}
	if nextCh > 0 {
		item["NextURL"] = fmt.Sprintf("/quran/%d/%d", nextCh, nextV)
	}

	renderTemplate(w, r, "quran.html", item)
}

func handleHadithView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/hadith/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetHadith(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, next := db.GetHadithPrevNext(id)
	item["PrevNumber"] = prev
	item["NextNumber"] = next
	renderTemplate(w, r, "hadith.html", item)
}

func handleNameView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/names/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetName(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, next := db.GetNamePrevNext(id)
	item["PrevNumber"] = prev
	item["NextNumber"] = next
	renderTemplate(w, r, "name.html", item)
}

func handleAPISearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"results": []interface{}{}})
		return
	}

	// Unified search across chats, entries, and notes.
	userID := getUserID(r)
	results, err := db.SearchAll(query, userID, isAdminReq(r), isLoggedIn(r))
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")

	var results []map[string]interface{}
	if query != "" {
		userID := getUserID(r)
		results, _ = db.SearchAll(query, userID, isAdminReq(r), isLoggedIn(r))
	}

	renderTemplate(w, r, "search.html", map[string]interface{}{
		"Query":   query,
		"Results": results,
	})
}

func handleEntries(w http.ResponseWriter, r *http.Request) {
	entries, _ := db.GetEntries(50)
	renderTemplate(w, r, "entries.html", map[string]interface{}{
		"Entries": entries,
	})
}

func handleGhazaliView(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/ghazali/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetGhazali(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, next := db.GetGhazaliPrevNext(slug)
	item["PrevSlug"] = prev
	item["NextSlug"] = next
	db.SaveReadingProgress(getUserID(r), "ghazali", r.URL.Path, item["Chapter"].(string))
	renderTemplate(w, r, "ghazali.html", item)
}

func handleGhazaliIndex(w http.ResponseWriter, r *http.Request) {
	volumeStr := r.URL.Query().Get("volume")
	data := map[string]interface{}{}

	if volumeStr != "" {
		volume, err := strconv.Atoi(volumeStr)
		if err == nil {
			chapters, _ := db.GetGhazaliByVolume(volume)
			data["Chapters"] = chapters
			data["SelectedVolume"] = volume
		}
	} else {
		chapters, _ := db.GetGhazaliChapters()
		data["Chapters"] = chapters
	}

	p, t := db.GetReadingProgress(getUserID(r), "ghazali")
	data["ContinuePath"] = p
	data["ContinueTitle"] = t

	renderTemplate(w, r, "ghazali_index.html", data)
}

func handleIslamQAView(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/islamqa/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetIslamQA(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, next := db.GetIslamQAPrevNext(slug)
	item["PrevSlug"] = prev
	item["NextSlug"] = next
	q, _ := item["Question"].(string)
	if len(q) > 60 {
		q = q[:60] + "..."
	}
	db.SaveReadingProgress(getUserID(r), "islamqa", r.URL.Path, q)
	renderTemplate(w, r, "islamqa.html", item)
}

func handleIslamQAIndex(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	data := map[string]interface{}{}

	categories, _ := db.GetIslamQACategories()
	data["Categories"] = categories

	if category != "" {
		questions, _ := db.GetIslamQAByCategory(category)
		data["Questions"] = questions
		data["SelectedCategory"] = category
	} else {
		questions, _ := db.GetAllIslamQA()
		data["Questions"] = questions
	}

	p, t := db.GetReadingProgress(getUserID(r), "islamqa")
	data["ContinuePath"] = p
	data["ContinueTitle"] = t

	renderTemplate(w, r, "islamqa_index.html", data)
}

func handleEntryView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/entries/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	entry, err := db.GetEntry(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	renderTemplate(w, r, "entry.html", entry)
}
