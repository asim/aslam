package db

import (
	"aslam/internal/seerah"
	"context"
	"fmt"
)

// IndexSeerah replaces the search index atomically when the reviewed dataset changes.
func IndexSeerah(book *seerah.Book) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS seerah_fts USING fts4(title, content, tokenize=unicode61)`); err != nil {
		return err
	}
	// A separate version table keeps this index transaction self-contained.
	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS seerah_version (id INTEGER PRIMARY KEY, version TEXT NOT NULL)`); err != nil {
		return err
	}
	var version string
	if err = tx.QueryRow(`SELECT version FROM seerah_version WHERE id=1`).Scan(&version); err == nil && version == seerah.Version() {
		return tx.Commit()
	}
	if _, err = tx.Exec(`DELETE FROM seerah_fts`); err != nil {
		return err
	}
	for _, p := range book.Pages {
		title := fmt.Sprintf("%s — page %d", book.Chapters[p.Chapter].Title, p.Number)
		if _, err = tx.Exec(`INSERT INTO seerah_fts(docid,title,content) VALUES(?,?,?)`, p.Number, title, p.Text()); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`INSERT OR REPLACE INTO seerah_version(id,version) VALUES(1,?)`, seerah.Version()); err != nil {
		return err
	}
	return tx.Commit()
}

func SearchSeerah(query string) ([]map[string]interface{}, error) {
	return SearchSeerahContext(context.Background(), query)
}

func SearchSeerahContext(ctx context.Context, query string) ([]map[string]interface{}, error) {
	return searchSeerahContext(ctx, query, 10)
}

func searchSeerahContext(ctx context.Context, query string, limit int) ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query = sanitiseFTS(query)
	if query == "" {
		return nil, nil
	}
	rows, err := DB.QueryContext(ctx, `SELECT docid,title,snippet(seerah_fts, '', '', ' … ', 1, 48) FROM seerah_fts WHERE seerah_fts MATCH ? LIMIT ?`, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []map[string]interface{}
	for rows.Next() {
		var page int
		var title, content string
		if err := rows.Scan(&page, &title, &content); err != nil {
			return nil, err
		}
		results = append(results, map[string]interface{}{"Kind": "seerah", "Title": title, "Content": content, "Role": "The Sealed Nectar — Safiur Rahman al-Mubarakpuri", "URL": fmt.Sprintf("/seerah/page/%d", page)})
	}
	return results, rows.Err()
}
