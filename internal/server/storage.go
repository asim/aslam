package server

import (
	"aslam/db"
)

// dbStorage implements tools.Storage interface
type dbStorage struct{}

func (s *dbStorage) SaveEntry(entryType, title, content, metadata string) (int64, error) {
	return db.SaveEntry(entryType, title, content, metadata)
}

func (s *dbStorage) GetEntryByTitle(entryType, title string) (map[string]interface{}, error) {
	return db.GetEntryByTitle(entryType, title)
}

func (s *dbStorage) SearchAll(query string, userID int64) ([]map[string]interface{}, error) {
	return db.SearchAll(query, userID, false, true)
}

// noteStorage implements tools.NoteStorage interface
type noteStorage struct{}

func (v *noteStorage) AddNoteItem(title, content string, userID int64) (int64, error) {
	return db.AddNoteItem(title, content, userID)
}

func (v *noteStorage) SearchNotes(query string, userID int64) ([]map[string]interface{}, error) {
	items, err := db.SearchNotes(query, userID, false)
	if err != nil {
		return nil, err
	}
	return noteItemsToMaps(items), nil
}

func (v *noteStorage) GetNoteItem(id int64) (map[string]interface{}, error) {
	item, err := db.GetNoteItem(id)
	if err != nil {
		return nil, err
	}
	return noteItemToMap(item), nil
}

func (v *noteStorage) UpdateNoteItem(id int64, updates map[string]interface{}) error {
	// Get current item, apply updates
	item, err := db.GetNoteItem(id)
	if err != nil {
		return err
	}

	title := item.Title
	content := item.Content

	if val, ok := updates["title"].(string); ok && val != "" {
		title = val
	}
	if val, ok := updates["content"].(string); ok {
		content = val
	}

	return db.UpdateNoteItem(id, title, content)
}

func noteItemToMap(item *db.NoteItem) map[string]interface{} {
	return map[string]interface{}{
		"ID":      item.ID,
		"Title":   item.Title,
		"Content": item.Content,
	}
}

func noteItemsToMaps(items []db.NoteItem) []map[string]interface{} {
	result := make([]map[string]interface{}, len(items))
	for i, item := range items {
		result[i] = map[string]interface{}{
			"ID":      item.ID,
			"Title":   item.Title,
			"Content": item.Content,
		}
	}
	return result
}
