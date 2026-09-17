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
)

var knowledgeCollections = map[string]string{
	"quran": "Quran", "hadith": "Sahih al-Bukhari", "names": "Names of Allah",
	"seerah":  "The Sealed Nectar — Safiur Rahman al-Mubarakpuri; translation by Issam Diab",
	"ghazali": "Ihya Ulum al-Din — Al-Ghazali", "islamqa": "IslamQA scholarly answers",
	"adhkar": "Duas and dhikr", "salihin": "Riyad us-Salihin",
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
		found, err := db.SearchKnowledgeContext(r.Context(), q, collection, limit)
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
	var item map[string]interface{}
	var err error
	number := func(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }
	switch {
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
	json.NewEncoder(w).Encode(map[string]interface{}{"kind": kind, "source": knowledgeCollections[kind], "url": "https://aslam.org" + path, "resource": item})
}
