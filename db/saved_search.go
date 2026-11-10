package db

import (
	"context"
	"fmt"
)

// SearchSaved retains FTS normalization without including unowned legacy caches.
func SearchSaved(query string, userID int64) ([]map[string]interface{}, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("account identity required")
	}
	query = sanitiseFTS(query)
	if query == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	messages, err := SearchMessagesContext(ctx, query, userID, false)
	if err != nil {
		return nil, err
	}
	var results []map[string]interface{}
	for _, m := range messages {
		results = append(results, map[string]interface{}{"Kind": "chat", "Title": m["Title"], "Content": m["Content"]})
	}
	notes, err := SearchNotesContext(ctx, query, userID, false)
	if err != nil {
		return nil, err
	}
	for _, n := range notes {
		results = append(results, map[string]interface{}{"Kind": "notes", "Title": n.Title, "Content": n.Content})
	}
	return results, nil
}
