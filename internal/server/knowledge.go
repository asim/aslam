package server

// The knowledge API is deliberately independent of sessions. It exposes only
// published reference collections, never conversations, notes or cached answers.
import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"aslam/db"
	"sort"
)

var knowledgeCollections = map[string]string{
	"tafsir": db.TafsirSource, "quran": "Quran", "hadith": "Sahih al-Bukhari", "names": "Names of Allah",
	"seerah":  "The Sealed Nectar — Safiur Rahman al-Mubarakpuri; translation by Issam Diab",
	"ghazali": "Ihya Ulum al-Din — Al-Ghazali", "islamqa": "IslamQA scholarly answers",
	"adhkar": "Duas and dhikr", "salihin": "Riyad us-Salihin",
	"arabic": "Quranic Arabic vocabulary", "roots": "Arabic roots", "reading": "Arabic reading passages", "stories": "Stories of the Prophets",
}

func handleKnowledgeSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		jsonError(w, "method not allowed", 405)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	collection := r.URL.Query().Get("collection")
	if len(q) > 1000 {
		jsonError(w, "query is too long", 400)
		return
	}
	if collection != "" && knowledgeCollections[collection] == "" {
		jsonError(w, "unknown collection", 400)
		return
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 50 {
			jsonError(w, "limit must be between 1 and 50", 400)
			return
		}
		limit = n
	}
	results := []map[string]interface{}{}
	if q != "" {
		var found []map[string]interface{}
		var err error
		if collection != "arabic" && collection != "roots" && collection != "reading" && collection != "stories" {
			found, err = db.SearchKnowledgeContext(r.Context(), q, collection, limit)
		}
		if err == nil {
			for _, kind := range []string{"arabic", "roots", "reading", "stories"} {
				if collection != "" && collection != kind {
					continue
				}
				extra, e := db.BrowseKnowledge(r.Context(), kind, "", q, 0, limit)
				if e != nil {
					err = e
					break
				}
				for _, item := range extra {
					item["Kind"] = kind
					found = append(found, item)
				}
			}
		}
		if err != nil {
			jsonError(w, "knowledge search unavailable", 500)
			return
		}
		for _, item := range found {
			kind, _ := item["Kind"].(string)
			if knowledgeCollections[kind] == "" || (collection != "" && collection != kind) {
				continue
			}
			item["Source"] = knowledgeCollections[kind]
			results = append(results, item)
			if len(results) == limit {
				break
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
}

// Resource paths use the same references as the reader and search results.
// No URL is fetched, and no user-owned resource type is accepted.
func handleKnowledgeResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		jsonError(w, "method not allowed", 405)
		return
	}
	path := r.URL.Query().Get("path")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if !strings.HasPrefix(path, "/") || len(parts) < 2 || knowledgeCollections[parts[0]] == "" {
		jsonError(w, "unknown knowledge resource", 400)
		return
	}
	kind := parts[0]
	if kind == "arabic" && len(parts) > 2 {
		if parts[1] == "roots" {
			kind = "roots"
		} else if parts[1] == "reading" {
			kind = "reading"
		}
	}
	var item map[string]interface{}
	var err error
	number := func(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }
	switch {
	case kind == "tafsir" && len(parts) == 4 && parts[1] == db.TafsirEdition:
		var passage *db.TafsirPassage
		passage, err = db.GetTafsir(r.Context(), int(number(parts[2])), int(number(parts[3])))
		if err == nil {
			item = map[string]interface{}{"Title": passage.Title, "Content": passage.Text, "HTML": passage.HTML, "Ayahs": passage.Ayahs, "Edition": db.TafsirEdition, "SourceURL": passage.SourceURL, "Previous": passage.Previous, "Next": passage.Next}
			path = passage.URL
		}
	case kind == "stories" && len(parts) == 2:
		item, err = db.GetProphetContext(r.Context(), parts[1])
	case kind == "arabic" && len(parts) == 2:
		item, err = db.GetArabicWordContext(r.Context(), number(parts[1]))
	case kind == "roots" && len(parts) == 3:
		var words []db.ArabicRootWord
		offset, _, pageErr := apiPage(r)
		if pageErr != nil {
			jsonError(w, pageErr.Error(), 400)
			return
		}
		words, err = db.ArabicRootWordsContext(r.Context(), parts[2], offset)
		if err == nil && len(words) == 0 {
			err = sql.ErrNoRows
		}
		next := ""
		if len(words) > 50 {
			words = words[:50]
			v := r.URL.Query()
			v.Set("offset", strconv.Itoa(offset+50))
			next = "/api/knowledge/resource?" + v.Encode()
		}
		item = map[string]interface{}{"Code": parts[2], "Words": words, "next": next}
	case kind == "reading" && len(parts) == 4:
		var passage *db.ArabicPassage
		passage, err = db.ArabicPassageContext(r.Context(), int(number(parts[2])), int(number(parts[3])))
		item = map[string]interface{}{"Passage": passage}
	case kind == "quran" && len(parts) == 3:
		item, err = db.GetQuranVerseContext(r.Context(), int(number(parts[1])), int(number(parts[2])))
	case kind == "hadith" && len(parts) == 2:
		item, err = db.GetHadithContext(r.Context(), number(parts[1]))
	case kind == "names" && len(parts) == 2:
		item, err = db.GetNameContext(r.Context(), number(parts[1]))
	case kind == "salihin" && len(parts) == 2:
		item, err = db.GetRiyadContext(r.Context(), number(parts[1]))
	case kind == "ghazali" && len(parts) == 2:
		item, err = db.GetGhazaliContext(r.Context(), parts[1])
	case kind == "islamqa" && len(parts) == 2:
		item, err = db.GetIslamQAContext(r.Context(), parts[1])
	case kind == "adhkar" && len(parts) == 2:
		item, err = db.GetAdhkarContext(r.Context(), parts[1])
	case kind == "seerah" && len(parts) == 3 && parts[1] == "page":
		if seerahBook == nil {
			jsonError(w, "seerah unavailable", 503)
			return
		}
		p, ok := seerahBook.Page(int(number(parts[2])))
		if !ok {
			err = sql.ErrNoRows
		} else {
			item = map[string]interface{}{"Title": fmt.Sprintf("%s — page %d", seerahBook.Chapters[p.Chapter].Title, p.Number), "Content": p.Text(), "Page": p.Number, "Author": seerahBook.Author, "Translator": seerahBook.Translator}
		}
	default:
		jsonError(w, "unknown knowledge resource", 400)
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, "resource not found", 404)
		return
	}
	if err != nil {
		jsonError(w, "knowledge resource unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	item, page, pageErr := paginateKnowledgeText(item, r.URL.Query())
	if pageErr != nil {
		jsonError(w, pageErr.Error(), 400)
		return
	}
	response := map[string]interface{}{"kind": kind, "source": knowledgeCollections[kind], "url": "https://aslam.org" + path, "resource": item}
	if page != nil {
		response["text_page"] = page
	}
	json.NewEncoder(w).Encode(response)
}

func apiPage(r *http.Request) (int, int, error) {
	offset, limit := 0, 20
	var err error
	if v := r.URL.Query().Get("offset"); v != "" {
		offset, err = strconv.Atoi(v)
		if err != nil || offset < 0 || offset > 100000 {
			return 0, 0, fmt.Errorf("offset must be 0–100000")
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil || limit < 1 || limit > 50 {
			return 0, 0, fmt.Errorf("limit must be 1–50")
		}
	}
	return offset, limit, nil
}
func apiJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func handleKnowledgeCollections(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonError(w, "Method not allowed", 405)
		return
	}
	keys := []string{}
	for k := range knowledgeCollections {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []map[string]string{}
	for _, k := range keys {
		out = append(out, map[string]string{"id": k, "title": knowledgeCollections[k], "browse": "/api/knowledge/browse?collection=" + k})
	}
	apiJSON(w, map[string]any{"collections": out})
}
func handleKnowledgeBrowse(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonError(w, "Method not allowed", 405)
		return
	}
	offset, limit, err := apiPage(r)
	if err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	kind := r.URL.Query().Get("collection")
	group := r.URL.Query().Get("group")
	if knowledgeCollections[kind] == "" || len(group) > 300 {
		jsonError(w, "Invalid collection or group", 400)
		return
	}
	var items []map[string]any
	if kind == "seerah" {
		if seerahBook == nil {
			jsonError(w, "Seerah unavailable", 503)
			return
		}
		items = []map[string]any{}
		for _, p := range seerahBook.Pages {
			if group != "" && group != strconv.Itoa(p.Chapter+1) {
				continue
			}
			items = append(items, map[string]any{"Page": p.Number, "Chapter": p.Chapter + 1, "Title": seerahBook.Chapters[p.Chapter].Title, "URL": fmt.Sprintf("/seerah/page/%d", p.Number)})
		}
		start := min(offset, len(items))
		items = items[start:min(start+limit+1, len(items))]
	} else {
		items, err = db.BrowseKnowledge(r.Context(), kind, group, "", offset, limit+1)
	}
	if err != nil {
		jsonError(w, "Content unavailable", 503)
		return
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	next := ""
	if more {
		v := r.URL.Query()
		v.Set("offset", strconv.Itoa(offset+limit))
		next = "/api/knowledge/browse?" + v.Encode()
	}
	for _, item := range items {
		item["Source"] = knowledgeCollections[kind]
	}
	apiJSON(w, map[string]any{"results": items, "next": next})
}
func handleKnowledgeContents(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonError(w, "Method not allowed", 405)
		return
	}
	kind := r.URL.Query().Get("collection")
	var items []map[string]interface{}
	var err error
	switch kind {
	case "tafsir":
		items, err = db.TafsirChapters(r.Context())
	case "quran":
		items, err = db.GetQuranChaptersContext(r.Context())
	case "hadith":
		items, err = db.GetHadithBooksContext(r.Context())
	case "salihin":
		items, err = db.GetRiyadBooksContext(r.Context())
	case "ghazali":
		items, err = db.GetGhazaliChaptersContext(r.Context())
	case "islamqa":
		items, err = db.GetIslamQACategoriesContext(r.Context())
	case "adhkar":
		items, err = db.GetAdhkarCategoriesContext(r.Context())
	case "seerah":
		if seerahBook == nil {
			jsonError(w, "Seerah unavailable", 503)
			return
		}
		apiJSON(w, map[string]any{"contents": seerahBook.Contents})
		return
	default:
		if knowledgeCollections[kind] == "" {
			jsonError(w, "Unknown collection", 400)
			return
		}
		apiJSON(w, map[string]any{"browse": "/api/knowledge/browse?collection=" + kind})
		return
	}
	if err != nil {
		jsonError(w, "Contents unavailable", 503)
		return
	}
	apiJSON(w, map[string]any{"contents": items})
}
