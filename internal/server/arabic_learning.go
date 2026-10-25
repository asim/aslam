package server

import (
	"aslam/db"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func handleArabicLearning(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/arabic/"), "/")
	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if r.URL.Query().Get("offset") == "" {
		offset = 0
		err = nil
	}
	if err != nil || offset < 0 || offset > 100000 {
		http.Error(w, "Invalid page", 400)
		return
	}
	d := map[string]interface{}{"Section": parts[0], "Path": r.URL.Path, "Offset": offset, "IndexURL": "/arabic/" + parts[0]}
	page := func(next bool) {
		q := r.URL.Query()
		if offset > 0 {
			q.Set("offset", strconv.Itoa(max(0, offset-50)))
			d["Prev"] = r.URL.Path + "?" + q.Encode()
		}
		if next {
			q.Set("offset", strconv.Itoa(offset+50))
			d["Next"] = r.URL.Path + "?" + q.Encode()
		}
	}
	fail := func(err error) bool {
		if err == nil {
			return false
		}
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Arabic content unavailable", 503)
		}
		return true
	}
	switch {
	case parts[0] == "roots" && len(parts) == 1:
		d["Title"] = "Roots"
		q := r.URL.Query().Get("q")
		d["Query"] = q
		roots, err := db.ArabicRootsContext(r.Context(), q, offset)
		if fail(err) {
			return
		}
		page(len(roots) > 50)
		if len(roots) > 50 {
			roots = roots[:50]
		}
		displayRoots := make([]arabicRootDisplay, 0, len(roots))
		for _, root := range roots {
			displayRoots = append(displayRoots, displayArabicRoot(root))
		}
		d["Roots"] = displayRoots
	case parts[0] == "roots" && len(parts) == 2 && parts[1] != "":
		roots, err := db.ArabicRootsContext(r.Context(), parts[1], 0)
		if fail(err) {
			return
		}
		if len(roots) != 1 || roots[0].Code != parts[1] {
			http.NotFound(w, r)
			return
		}
		root := roots[0]
		displayRoot := displayArabicRoot(root)
		d["Title"] = "Root: " + strings.Join(displayRoot.Letters, " ")
		d["Root"] = displayRoot
		words, err := db.ArabicRootWordsContext(r.Context(), root.Code, offset)
		if fail(err) {
			return
		}
		page(len(words) > 50)
		if len(words) > 50 {
			words = words[:50]
		}
		d["RootWords"] = words
		d["WordPrev"], d["WordNext"] = d["Prev"], d["Next"]
		delete(d, "Prev")
		delete(d, "Next")
		prev, next, indexOffset, err := db.ArabicRootNavigationContext(r.Context(), root.Code)
		if fail(err) {
			return
		}
		if prev != "" {
			d["Prev"] = "/arabic/roots/" + url.PathEscape(prev)
		}
		if next != "" {
			d["Next"] = "/arabic/roots/" + url.PathEscape(next)
		}
		d["IndexURL"] = fmt.Sprintf("/arabic/roots?offset=%d", indexOffset)

		context := fmt.Sprintf("Quranic Arabic root %s (%s). Source: https://corpus.quran.com\n", root.Arabic, root.Code)
		for _, word := range words {
			context += fmt.Sprintf("%s (%s) — %s; lemma %s; %s\n", word.Arabic, word.Transliteration, word.English, word.Lemma, word.Type)
		}
		d["Context"] = context
		d["Detail"] = true
	case parts[0] == "reading" && len(parts) == 1:
		level := r.URL.Query().Get("level")
		minWords, maxWords := 1, 5
		switch level {
		case "", "short":
			level = "short"
		case "medium":
			minWords, maxWords = 6, 10
		case "long":
			minWords, maxWords = 11, 1000
		default:
			http.Error(w, "Invalid length", 400)
			return
		}
		d["Title"] = "Phrases & verses"
		d["Level"] = level
		passages, err := db.ArabicPassagesContext(r.Context(), minWords, maxWords, offset)
		if fail(err) {
			return
		}
		page(len(passages) > 50)
		if len(passages) > 50 {
			passages = passages[:50]
		}
		d["Passages"] = passages
	case parts[0] == "reading" && len(parts) == 3:
		ch, e1 := strconv.Atoi(parts[1])
		v, e2 := strconv.Atoi(parts[2])
		if e1 != nil || e2 != nil || ch < 1 || v < 1 {
			http.NotFound(w, r)
			return
		}
		p, err := db.ArabicPassageContext(r.Context(), ch, v)
		if fail(err) {
			return
		}
		d["Title"], d["Passage"], d["Detail"] = p.Title, p, true
		prev, next, indexOffset, err := db.ArabicPassageNavigationContext(r.Context(), p)
		if fail(err) {
			return
		}
		d["Prev"], d["Next"] = prev, next
		level := "short"
		if len(p.Words) > 10 {
			level = "long"
		} else if len(p.Words) > 5 {
			level = "medium"
		}
		d["IndexURL"] = fmt.Sprintf("/arabic/reading?level=%s&offset=%d", level, indexOffset)

		context := fmt.Sprintf("Quran %s\n%s\n%s\n", p.Title, p.Arabic, p.English)
		for _, word := range p.Words {
			context += fmt.Sprintf("%s (%s) — %s\n", word.Arabic, word.Transliteration, word.English)
		}
		d["Context"] = context
	default:
		http.NotFound(w, r)
		return
	}
	userID := getUserID(r)
	if d["Detail"] == true {
		path := r.URL.Path
		if offset > 0 {
			path += "?offset=" + url.QueryEscape(strconv.Itoa(offset))
		}
		db.SaveReadingProgressContext(r.Context(), userID, "arabic", path, d["Title"].(string))
	} else {
		d["ContinuePath"], d["ContinueTitle"] = db.GetReadingProgressContext(r.Context(), userID, "arabic")
	}
	renderTemplate(w, r, "arabic_learning.html", d)
}

type arabicRootDisplay struct {
	db.ArabicRootSummary
	Letters       []string
	Pronunciation string
}

func displayArabicRoot(root db.ArabicRootSummary) arabicRootDisplay {
	// Display consonants separately; retain the corpus code for URLs and lookups.
	sounds := map[rune]string{
		'ء': "ʾ", 'ا': "ʾ", 'أ': "ʾ", 'إ': "ʾ", 'ؤ': "ʾ", 'ئ': "ʾ",
		'ب': "b", 'ت': "t", 'ث': "th", 'ج': "j", 'ح': "ḥ", 'خ': "kh",
		'د': "d", 'ذ': "dh", 'ر': "r", 'ز': "z", 'س': "s", 'ش': "sh",
		'ص': "ṣ", 'ض': "ḍ", 'ط': "ṭ", 'ظ': "ẓ", 'ع': "ʿ", 'غ': "gh",
		'ف': "f", 'ق': "q", 'ك': "k", 'ل': "l", 'م': "m", 'ن': "n",
		'ه': "h", 'و': "w", 'ي': "y", 'ى': "y",
	}
	result := arabicRootDisplay{ArabicRootSummary: root}
	var latin []string
	for _, letter := range root.Arabic {
		result.Letters = append(result.Letters, string(letter))
		sound, ok := sounds[letter]
		if !ok {
			sound = string(letter)
		}
		latin = append(latin, sound)
	}
	result.Pronunciation = strings.Join(latin, "-")
	return result
}
