package db

import (
	"context"
	"hash/fnv"
)

// GetIslamQAPageContext bounds the question index, including category views.
func GetIslamQAPageContext(ctx context.Context, category string, offset int) ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	query := `SELECT id,COALESCE(slug,''),category,question FROM islamqa`
	args := []interface{}{}
	if category != "" {
		query += ` WHERE category=?`
		args = append(args, category)
	}
	query += ` ORDER BY category,id LIMIT 51 OFFSET ?`
	args = append(args, offset)
	rows, err := DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id int64
		var slug, cat, question string
		if err = rows.Scan(&id, &slug, &cat, &question); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{"ID": id, "Slug": slug, "Category": cat, "Question": question})
	}
	return out, rows.Err()
}

func GetDailyIslamQAContext(ctx context.Context, date string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	var count int
	if err := DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM islamqa`).Scan(&count); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	h := fnv.New32a()
	h.Write([]byte(date))
	offset := int(h.Sum32() % uint32(count))
	var id int64
	var slug, category, question string
	err := DB.QueryRowContext(ctx, `SELECT id,COALESCE(slug,''),category,question FROM islamqa ORDER BY id LIMIT 1 OFFSET ?`, offset).Scan(&id, &slug, &category, &question)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"ID": id, "Slug": slug, "Category": category, "Question": question}, nil
}

func GetRecentNotesContext(ctx context.Context, userID int64) ([]NoteItem, error) {
	if userID == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := DB.QueryContext(ctx, `SELECT id,title,updated_at FROM notes_v2 WHERE user_id=? ORDER BY updated_at DESC,id DESC LIMIT 3`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var notes []NoteItem
	for rows.Next() {
		var n NoteItem
		if err = rows.Scan(&n.ID, &n.Title, &n.UpdatedAt); err != nil {
			return nil, err
		}
		notes = append(notes, n)
	}
	return notes, rows.Err()
}
