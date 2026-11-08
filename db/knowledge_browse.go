package db

import (
	"context"
	"fmt"
	"strings"
)

// QueryAPI reads only fixed application queries supplied by handlers, never SQL
// from clients. Callers bind all user input and include a bounded LIMIT.
func QueryAPI(ctx context.Context, query string, args ...any) ([]map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		item := map[string]any{}
		for i, name := range cols {
			if b, ok := values[i].([]byte); ok {
				item[name] = string(b)
			} else {
				item[name] = values[i]
			}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func BrowseKnowledge(ctx context.Context, collection, group, q string, offset, limit int) ([]map[string]any, error) {
	var query, filter, search, order string
	switch collection {
	case "quran":
		query = `SELECT chapter,chapter_name AS Title,verse,arabic,text AS Content,'/quran/'||chapter||'/'||verse AS URL FROM quran`
		filter = "CAST(chapter AS TEXT)"
		search = "text || ' ' || COALESCE(arabic,'')"
		order = "chapter,verse"
	case "hadith":
		query = `SELECT book,book_number,number,narrator,substr(text,1,300) AS Content,'/hadith/'||number AS URL FROM hadith`
		filter = "CAST(book_number AS TEXT)"
		search = "text"
		order = "number,id"
	case "names":
		query = `SELECT number,english AS Title,arabic,meaning AS Content,'/names/'||number AS URL FROM names`
		filter = "''"
		search = "english || ' ' || COALESCE(meaning,'')"
		order = "number,id"
	case "ghazali":
		query = `SELECT volume,volume_title,chapter AS Title,part,substr(content,1,300) AS Content,'/ghazali/'||slug AS URL FROM ghazali`
		filter = "CAST(volume AS TEXT)"
		search = "chapter || ' ' || content"
		order = "volume,id"
	case "islamqa":
		query = `SELECT category,question AS Title,substr(answer,1,300) AS Content,'/islamqa/'||slug AS URL FROM islamqa`
		filter = "category"
		search = "question || ' ' || answer"
		order = "id"
	case "adhkar":
		query = `SELECT category,title AS Title,arabic,translation AS Content,'/adhkar/'||slug AS URL FROM adhkar`
		filter = "category"
		search = "title || ' ' || COALESCE(translation,'')"
		order = "id"
	case "salihin":
		query = `SELECT book,number,narrator,substr(text,1,300) AS Content,'/salihin/'||number AS URL FROM salihin`
		filter = "book"
		search = "text"
		order = "number,id"
	case "stories":
		query = `SELECT name AS Title,arabic,summary AS Content,'/stories/'||slug AS URL FROM prophets`
		filter = "''"
		search = "name || ' ' || COALESCE(summary,'')"
		order = "sort_order,id"
	case "arabic":
		query = `SELECT id,arabic AS Title,transliteration,english AS Content,frequency,type,example_ref,'/arabic/'||id AS URL FROM arabic`
		filter = "type"
		search = "arabic || ' ' || COALESCE(transliteration,'') || ' ' || COALESCE(english,'')"
		order = "frequency DESC,id"
	case "roots":
		query = `SELECT code AS Title,arabic,count(DISTINCT word_id) AS words,'/arabic/roots/'||code AS URL FROM arabic_roots`
		filter = "code"
		search = "code || ' ' || arabic"
		order = "code"
	case "reading":
		query = `SELECT chapter,verse,title AS Title,arabic,english AS Content,word_count,'/arabic/reading/'||chapter||'/'||verse AS URL FROM arabic_passages`
		filter = "CAST(chapter AS TEXT)"
		search = "arabic || ' ' || english"
		order = "word_count,chapter,verse"
	default:
		return nil, fmt.Errorf("unknown collection")
	}
	query += " WHERE (?='' OR " + filter + "=?) AND (?='' OR " + search + " LIKE ? ESCAPE '\\')"
	if collection == "roots" {
		query += " GROUP BY code,arabic"
	}
	query += " ORDER BY " + order + " LIMIT ? OFFSET ?"
	return QueryAPI(ctx, query, group, group, q, "%"+escapeLike(q)+"%", limit, offset)
}

func escapeLike(s string) string {
	return strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(s)
}
