package server

import (
	"aslam/data"
	"encoding/json"
	"fmt"
	"sync"
)

var quranChaptersOnce sync.Once
var quranChapterIndex []map[string]interface{}
var quranChapterError error

// Chapter metadata is immutable source data, decoded once rather than grouped
// from all verse rows on each index request. Personal progress is still per-user.
func quranChapters() ([]map[string]interface{}, error) {
	quranChaptersOnce.Do(func() {
		var source struct {
			Chapters []struct {
				ID          int    `json:"id"`
				Name        string `json:"name_simple"`
				Arabic      string `json:"name_arabic"`
				Count       int    `json:"verses_count"`
				Translation struct {
					Name string `json:"name"`
				} `json:"translated_name"`
			} `json:"chapters"`
		}
		if err := json.Unmarshal(data.QuranChapters, &source); err != nil {
			quranChapterError = err
			return
		}
		if len(source.Chapters) != 114 {
			quranChapterError = fmt.Errorf("incomplete Quran chapter metadata")
			return
		}
		for i, ch := range source.Chapters {
			if ch.ID != i+1 || ch.Arabic == "" || ch.Translation.Name == "" {
				quranChapterError = fmt.Errorf("invalid chapter %d", ch.ID)
				return
			}
			quranChapterIndex = append(quranChapterIndex, map[string]interface{}{"Chapter": ch.ID, "Name": ch.Name, "Arabic": ch.Arabic, "Meaning": ch.Translation.Name, "Count": ch.Count})
		}
	})
	return quranChapterIndex, quranChapterError
}
