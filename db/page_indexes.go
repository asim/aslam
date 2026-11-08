package db

// Match the filters and ordering used by reader pages and the home screen.
// Index keys exclude the large text fields stored in the source tables.
func initPageIndexes() error {
	_, err := DB.Exec(`
 CREATE INDEX IF NOT EXISTS idx_quran_chapter_verse ON quran(chapter,verse);
 CREATE INDEX IF NOT EXISTS idx_hadith_number ON hadith(number);
 CREATE INDEX IF NOT EXISTS idx_hadith_book_number ON hadith(book_number,number);
 CREATE INDEX IF NOT EXISTS idx_islamqa_category_id ON islamqa(category,id);
 CREATE INDEX IF NOT EXISTS idx_ghazali_volume_chapter ON ghazali(volume,chapter,id);
 CREATE INDEX IF NOT EXISTS idx_arabic_frequency ON arabic(frequency DESC);
 CREATE INDEX IF NOT EXISTS idx_notes_v2_user_updated ON notes_v2(user_id,updated_at DESC,id DESC);
 CREATE INDEX IF NOT EXISTS idx_conversations_user_updated ON conversations(user_id,updated_at DESC);
 CREATE INDEX IF NOT EXISTS idx_conversations_updated ON conversations(updated_at DESC);
 CREATE INDEX IF NOT EXISTS idx_reminder_content_fetched ON reminder_content(fetched_at DESC);
 `)
	return err
}
