package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

var DB *sql.DB

type Conversation struct {
	ID        int64
	Title     string
	Summary   sql.NullString
	UserID    int64
	Public    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Message struct {
	ID             int64
	ConversationID int64
	Role           string
	Content        string
	CreatedAt      time.Time
}

type Session struct {
	Token     string
	Email     string
	Name      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Init initializes the database connection
func Init() error {
	dbKey := os.Getenv("ASLAM_KEY")
	if dbKey == "" {
		keyPath := filepath.Join(os.Getenv("HOME"), ".aslam", ".key")
		if data, err := os.ReadFile(keyPath); err == nil {
			dbKey = strings.TrimSpace(string(data))
		}
	}
	if dbKey == "" {
		return fmt.Errorf("ASLAM_KEY not set and ~/.aslam/.key not found")
	}

	dbPath := os.Getenv("ASLAM_DB")
	if dbPath == "" {
		dbPath = filepath.Join(os.Getenv("HOME"), ".aslam", "aslam.db")
	}

	encodedKey := url.QueryEscape(dbKey)
	dsn := fmt.Sprintf("%s?_pragma_key=%s&_pragma_cipher_page_size=4096", dbPath, encodedKey)
	
	var err error
	DB, err = sql.Open("sqlite3", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	return Migrate()
}

// Close closes the database connection
func Close() {
	if DB != nil {
		DB.Close()
	}
}

// Migrate runs database migrations
func Migrate() error {
	// Conversations
	_, err := DB.Exec(`
		CREATE TABLE IF NOT EXISTS conversations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			summary TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Messages
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			conversation_id INTEGER NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
			content TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	// FTS for messages
	_, err = DB.Exec(`
		CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts4(
			content,
			content='messages'
		)
	`)
	if err != nil {
		return err
	}

	// Triggers for FTS
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
		INSERT INTO messages_fts(docid, content) VALUES (new.id, new.content);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
		DELETE FROM messages_fts WHERE docid = old.id;
	END`)
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id)`)

	// Sessions
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			name TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// OAuth states
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS oauth_states (
			state TEXT PRIMARY KEY,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// Clean up expired
	DB.Exec(`DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP`)
	DB.Exec(`DELETE FROM oauth_states WHERE expires_at < CURRENT_TIMESTAMP`)

	// Email threads - maps email threads to conversations
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS email_threads (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			thread_id TEXT UNIQUE NOT NULL,
			conversation_id INTEGER NOT NULL,
			last_message_id TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	// Email log - all incoming/outgoing emails
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS email_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			message_id TEXT UNIQUE,
			thread_id TEXT,
			direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
			from_email TEXT NOT NULL,
			to_email TEXT NOT NULL,
			subject TEXT,
			body TEXT,
			status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processed', 'failed')),
			error TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			processed_at DATETIME
		)
	`)
	if err != nil {
		return err
	}
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_email_log_status ON email_log(status)`)
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_email_log_thread ON email_log(thread_id)`)

	// Pending tasks - unified queue for all channels
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS pending_tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			channel TEXT NOT NULL,
			conversation_id INTEGER NOT NULL,
			reference_id TEXT,
			status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
			attempts INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 3,
			last_error TEXT,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_pending_tasks_status ON pending_tasks(status)`)
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_pending_tasks_channel ON pending_tasks(channel)`)

	// Accounts/credentials - for estate planning and handover
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			service TEXT NOT NULL,
			account_id TEXT,
			password TEXT,
			api_key TEXT,
			description TEXT,
			url TEXT,
			env_var TEXT,
			notes TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}
	// Add new columns if they don't exist (migration for existing DBs)
	DB.Exec(`ALTER TABLE accounts ADD COLUMN password TEXT`)
	DB.Exec(`ALTER TABLE accounts ADD COLUMN api_key TEXT`)
	DB.Exec(`ALTER TABLE accounts ADD COLUMN url TEXT`)

	// Add password_hash column to users (migration for existing DBs)
	DB.Exec(`ALTER TABLE users ADD COLUMN password_hash TEXT`)
	DB.Exec(`ALTER TABLE users ADD COLUMN picture TEXT`)
	DB.Exec(`ALTER TABLE users ADD COLUMN latitude REAL DEFAULT 0`)
	DB.Exec(`ALTER TABLE users ADD COLUMN longitude REAL DEFAULT 0`)
	DB.Exec(`ALTER TABLE users ADD COLUMN timezone TEXT DEFAULT ''`)

	// Users - people who can access the system
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			name TEXT,
			role TEXT DEFAULT 'admin',
			added_by TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Migrate data from legacy admins table if it exists
	DB.Exec(`INSERT OR IGNORE INTO users SELECT * FROM admins`)

	// Settings - key/value store for configuration
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Notes - things to keep track of (assets, accounts, people, instructions, documents)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS notes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			category TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			details TEXT,
			credentials TEXT,
			notes TEXT,
			status TEXT DEFAULT 'active',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}
	// Migrate data from vault table if it exists
	DB.Exec(`INSERT OR IGNORE INTO notes SELECT * FROM vault`)
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_notes_category ON notes(category)`)
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_notes_status ON notes(status)`)

	// Simplified notes (notes_v2)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS notes_v2 (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			content TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Migrate data from old notes table to notes_v2
	DB.Exec(`INSERT OR IGNORE INTO notes_v2 (id, title, content, created_at, updated_at)
		SELECT id, name,
			COALESCE(details, '') ||
			CASE WHEN credentials != '' AND credentials IS NOT NULL THEN char(10) || char(10) || credentials ELSE '' END ||
			CASE WHEN notes != '' AND notes IS NOT NULL THEN char(10) || char(10) || notes ELSE '' END,
			created_at, updated_at
		FROM notes`)

	// FTS for notes_v2
	_, err = DB.Exec(`
		CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts4(
			title,
			content,
			content='notes_v2'
		)
	`)
	if err != nil {
		return err
	}

	DB.Exec(`CREATE TRIGGER IF NOT EXISTS notes_v2_ai AFTER INSERT ON notes_v2 BEGIN
		INSERT INTO notes_fts(docid, title, content) VALUES (new.id, new.title, new.content);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS notes_v2_ad AFTER DELETE ON notes_v2 BEGIN
		DELETE FROM notes_fts WHERE docid = old.id;
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS notes_v2_au AFTER UPDATE ON notes_v2 BEGIN
		DELETE FROM notes_fts WHERE docid = old.id;
		INSERT INTO notes_fts(docid, title, content) VALUES (new.id, new.title, new.content);
	END`)

	// Entries (knowledge base)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			title TEXT NOT NULL,
			content TEXT,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// FTS for entries
	_, err = DB.Exec(`
		CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts4(
			title,
			content,
			content='entries'
		)
	`)
	if err != nil {
		return err
	}

	DB.Exec(`CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries BEGIN
		INSERT INTO entries_fts(docid, title, content) VALUES (new.id, new.title, new.content);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries BEGIN
		DELETE FROM entries_fts WHERE docid = old.id;
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS entries_au AFTER UPDATE ON entries BEGIN
		DELETE FROM entries_fts WHERE docid = old.id;
		INSERT INTO entries_fts(docid, title, content) VALUES (new.id, new.title, new.content);
	END`)

	// Add user_id and public columns to conversations and notes_v2
	DB.Exec(`ALTER TABLE conversations ADD COLUMN user_id INTEGER REFERENCES users(id)`)
	DB.Exec(`ALTER TABLE conversations ADD COLUMN public INTEGER DEFAULT 0`)
	DB.Exec(`ALTER TABLE notes_v2 ADD COLUMN user_id INTEGER REFERENCES users(id)`)
	DB.Exec(`ALTER TABLE notes_v2 ADD COLUMN public INTEGER DEFAULT 0`)
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id)`)
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_notes_v2_user ON notes_v2(user_id)`)

	// Reminder — cached Q&A from the reminder API (Quran, Hadith, Names of Allah)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS reminder (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			question TEXT NOT NULL,
			answer TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}
	DB.Exec(`
		CREATE VIRTUAL TABLE IF NOT EXISTS reminder_fts USING fts4(
			question,
			answer,
			content='reminder'
		)
	`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS reminder_ai AFTER INSERT ON reminder BEGIN
		INSERT INTO reminder_fts(docid, question, answer) VALUES (new.id, new.question, new.answer);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS reminder_ad AFTER DELETE ON reminder BEGIN
		DELETE FROM reminder_fts WHERE docid = old.id;
	END`)

	// IslamQA
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS islamqa (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			category TEXT NOT NULL,
			question TEXT NOT NULL,
			answer TEXT NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// FTS for islamqa
	_, err = DB.Exec(`
		CREATE VIRTUAL TABLE IF NOT EXISTS islamqa_fts USING fts4(
			question,
			answer,
			content='islamqa'
		)
	`)
	if err != nil {
		return err
	}

	DB.Exec(`CREATE TRIGGER IF NOT EXISTS islamqa_ai AFTER INSERT ON islamqa BEGIN
		INSERT INTO islamqa_fts(docid, question, answer) VALUES (new.id, new.question, new.answer);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS islamqa_ad AFTER DELETE ON islamqa BEGIN
		DELETE FROM islamqa_fts WHERE docid = old.id;
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS islamqa_au AFTER UPDATE ON islamqa BEGIN
		DELETE FROM islamqa_fts WHERE docid = old.id;
		INSERT INTO islamqa_fts(docid, question, answer) VALUES (new.id, new.question, new.answer);
	END`)

	// Ghazali — Ihya Ulum al-Din (Revival of the Islamic Sciences)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS ghazali (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			volume INTEGER NOT NULL,
			volume_title TEXT NOT NULL,
			chapter TEXT NOT NULL,
			part INTEGER DEFAULT 1,
			content TEXT NOT NULL
		)
	`)
	if err != nil {
		return err
	}
	DB.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS ghazali_fts USING fts4(
		chapter, content, content='ghazali'
	)`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS ghazali_ai AFTER INSERT ON ghazali BEGIN
		INSERT INTO ghazali_fts(docid, chapter, content) VALUES (new.id, new.chapter, new.content);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS ghazali_ad AFTER DELETE ON ghazali BEGIN
		DELETE FROM ghazali_fts WHERE docid = old.id;
	END`)

	// Daily content — cached daily reminder (verse, hadith, name of Allah)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS daily_content (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			verse TEXT,
			hadith TEXT,
			name_of_allah TEXT,
			message TEXT,
			verse_link TEXT,
			hadith_link TEXT,
			name_link TEXT,
			fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Rename: reminder → searches (cached search results from reminder API)
	DB.Exec(`CREATE TABLE IF NOT EXISTS searches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		question TEXT NOT NULL,
		answer TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	DB.Exec(`INSERT OR IGNORE INTO searches SELECT * FROM reminder WHERE typeof(id) = 'integer'`)
	DB.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS searches_fts USING fts4(
		question, answer, content='searches'
	)`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS searches_ai AFTER INSERT ON searches BEGIN
		INSERT INTO searches_fts(docid, question, answer) VALUES (new.id, new.question, new.answer);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS searches_ad AFTER DELETE ON searches BEGIN
		DELETE FROM searches_fts WHERE docid = old.id;
	END`)
	// Rebuild FTS index for migrated data
	DB.Exec(`INSERT INTO searches_fts(searches_fts) VALUES('rebuild')`)

	// Rename: daily_content → reminder_content (the daily feed from reminder.dev)
	DB.Exec(`CREATE TABLE IF NOT EXISTS reminder_content (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		verse TEXT,
		hadith TEXT,
		name_of_allah TEXT,
		message TEXT,
		verse_link TEXT,
		hadith_link TEXT,
		name_link TEXT,
		fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	DB.Exec(`INSERT OR IGNORE INTO reminder_content SELECT * FROM daily_content WHERE typeof(id) = 'integer'`)

	// Quran — full text of the Quran with translations and commentary
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS quran (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			chapter INTEGER NOT NULL,
			chapter_name TEXT NOT NULL,
			verse INTEGER NOT NULL,
			text TEXT NOT NULL,
			arabic TEXT,
			commentary TEXT
		)
	`)
	if err != nil {
		return err
	}
	DB.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS quran_fts USING fts4(
		text, commentary, content='quran'
	)`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS quran_ai AFTER INSERT ON quran BEGIN
		INSERT INTO quran_fts(docid, text, commentary) VALUES (new.id, new.text, new.commentary);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS quran_ad AFTER DELETE ON quran BEGIN
		DELETE FROM quran_fts WHERE docid = old.id;
	END`)

	// Hadith — Sahih al-Bukhari
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS hadith (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			book TEXT NOT NULL,
			number INTEGER,
			narrator TEXT,
			text TEXT NOT NULL,
			arabic TEXT
		)
	`)
	if err != nil {
		return err
	}
	DB.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS hadith_fts USING fts4(
		text, narrator, content='hadith'
	)`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS hadith_ai AFTER INSERT ON hadith BEGIN
		INSERT INTO hadith_fts(docid, text, narrator) VALUES (new.id, new.text, new.narrator);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS hadith_ad AFTER DELETE ON hadith BEGIN
		DELETE FROM hadith_fts WHERE docid = old.id;
	END`)

	// Names of Allah — 99 names with meanings and descriptions
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS names (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			number INTEGER NOT NULL,
			english TEXT NOT NULL,
			arabic TEXT,
			meaning TEXT,
			description TEXT,
			summary TEXT
		)
	`)
	if err != nil {
		return err
	}
	DB.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS names_fts USING fts4(
		english, meaning, description, summary, content='names'
	)`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS names_ai AFTER INSERT ON names BEGIN
		INSERT INTO names_fts(docid, english, meaning, description, summary) VALUES (new.id, new.english, new.meaning, new.description, new.summary);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS names_ad AFTER DELETE ON names BEGIN
		DELETE FROM names_fts WHERE docid = old.id;
	END`)

	// Tags
	DB.Exec(`
		CREATE TABLE IF NOT EXISTS tags (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL
		)
	`)
	DB.Exec(`
		CREATE TABLE IF NOT EXISTS entry_tags (
			entry_id INTEGER NOT NULL,
			tag_id INTEGER NOT NULL,
			PRIMARY KEY (entry_id, tag_id),
			FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE,
			FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
		)
	`)

	// Adhkar (duas/dhikr)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS adhkar (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			category TEXT NOT NULL,
			title TEXT NOT NULL,
			arabic TEXT,
			transliteration TEXT,
			translation TEXT,
			notes TEXT,
			benefits TEXT,
			source TEXT
		)
	`)
	if err != nil {
		return err
	}

	DB.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS adhkar_fts USING fts4(
		title, translation, benefits, content='adhkar'
	)`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS adhkar_ai AFTER INSERT ON adhkar BEGIN
		INSERT INTO adhkar_fts(docid, title, translation, benefits) VALUES (new.id, new.title, new.translation, new.benefits);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS adhkar_ad AFTER DELETE ON adhkar BEGIN
		DELETE FROM adhkar_fts WHERE docid = old.id;
	END`)

	// Riyad us-Saliheen (Gardens of the Righteous) by Imam An-Nawawi
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS salihin (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			book TEXT NOT NULL,
			number INTEGER,
			narrator TEXT,
			text TEXT NOT NULL,
			arabic TEXT
		)
	`)
	if err != nil {
		return err
	}
	DB.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS salihin_fts USING fts4(
		text, narrator, content='salihin'
	)`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS salihin_ai AFTER INSERT ON salihin BEGIN
		INSERT INTO salihin_fts(docid, text, narrator) VALUES (new.id, new.text, new.narrator);
	END`)
	DB.Exec(`CREATE TRIGGER IF NOT EXISTS salihin_ad AFTER DELETE ON salihin BEGIN
		DELETE FROM salihin_fts WHERE docid = old.id;
	END`)

	return nil
}

// Conversation functions

func GetRecentConversations(limit int, userID int64, mineOnly bool) ([]Conversation, error) {
	var query string
	var args []interface{}
	if mineOnly {
		query = `SELECT id, title, summary, COALESCE(user_id, 0), COALESCE(public, 0), created_at, updated_at
			FROM conversations WHERE user_id = ? OR user_id IS NULL ORDER BY updated_at DESC LIMIT ?`
		args = []interface{}{userID, limit}
	} else {
		query = `SELECT id, title, summary, COALESCE(user_id, 0), COALESCE(public, 0), created_at, updated_at
			FROM conversations WHERE user_id = ? OR public = 1 OR user_id IS NULL ORDER BY updated_at DESC LIMIT ?`
		args = []interface{}{userID, limit}
	}
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var convs []Conversation
	for rows.Next() {
		var c Conversation
		var pub int
		rows.Scan(&c.ID, &c.Title, &c.Summary, &c.UserID, &pub, &c.CreatedAt, &c.UpdatedAt)
		c.Public = pub == 1
		convs = append(convs, c)
	}
	return convs, nil
}

func GetConversation(id int64) (*Conversation, error) {
	var c Conversation
	var pub int
	err := DB.QueryRow(`
		SELECT id, title, summary, COALESCE(user_id, 0), COALESCE(public, 0), created_at, updated_at
		FROM conversations WHERE id = ?
	`, id).Scan(&c.ID, &c.Title, &c.Summary, &c.UserID, &pub, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	c.Public = pub == 1
	return &c, nil
}

func CreateConversation(title string, userID int64) (int64, error) {
	result, err := DB.Exec(`INSERT INTO conversations (title, user_id) VALUES (?, ?)`, title, userID)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func UpdateConversationTitle(id int64, title string) error {
	_, err := DB.Exec(`UPDATE conversations SET title = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, title, id)
	return err
}

func DeleteConversation(id int64) error {
	_, err := DB.Exec(`DELETE FROM conversations WHERE id = ?`, id)
	return err
}

// Message functions

func GetMessages(convID int64) ([]Message, error) {
	rows, err := DB.Query(`
		SELECT id, conversation_id, role, content, created_at 
		FROM messages 
		WHERE conversation_id = ? 
		ORDER BY created_at ASC
	`, convID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []Message
	for rows.Next() {
		var m Message
		rows.Scan(&m.ID, &m.ConversationID, &m.Role, &m.Content, &m.CreatedAt)
		msgs = append(msgs, m)
	}
	return msgs, nil
}

func AddMessage(convID int64, role, content string) error {
	_, err := DB.Exec(`
		INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)
	`, convID, role, content)
	if err != nil {
		return err
	}
	DB.Exec(`UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?`, convID)
	return nil
}

func SearchMessages(query string, userID int64) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT m.id, m.conversation_id, m.role, m.content, m.created_at, c.title
		FROM messages m
		JOIN messages_fts fts ON m.id = fts.docid
		JOIN conversations c ON m.conversation_id = c.id
		WHERE messages_fts MATCH ?
		AND (c.user_id = ? OR c.public = 1 OR c.user_id IS NULL)
		ORDER BY m.created_at DESC
		LIMIT 50
	`, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id, convID int64
		var role, content, title string
		var createdAt time.Time
		rows.Scan(&id, &convID, &role, &content, &createdAt, &title)
		results = append(results, map[string]interface{}{
			"ID":             id,
			"ConversationID": convID,
			"Role":           role,
			"Content":        content,
			"CreatedAt":      createdAt,
			"Title":          title,
		})
	}
	return results, nil
}

// SearchAll runs a query across chats, entries, and note items and returns a
// unified list of results. Each result has a "Kind" field ("chat", "entry",
// "notes") that the UI uses to render the right kind of link.
//
// This is the backbone of the knowledge base: anything the user has ever asked
// the assistant, anything the assistant remembered, and anything stored in
// notes can be found with a single query.
func SearchAll(query string, userID int64) ([]map[string]interface{}, error) {
	if strings.TrimSpace(query) == "" {
		return nil, nil
	}

	var results []map[string]interface{}

	// Chats (messages + conversation title)
	if msgs, err := SearchMessages(query, userID); err == nil {
		for _, m := range msgs {
			createdAt, _ := m["CreatedAt"].(time.Time)
			results = append(results, map[string]interface{}{
				"Kind":      "chat",
				"Title":     m["Title"],
				"Content":   m["Content"],
				"Role":      m["Role"],
				"URL":       fmt.Sprintf("/chat/%d", m["ConversationID"]),
				"CreatedAt": createdAt,
			})
		}
	}

	// Entries (notes, remembered facts, fetched URLs)
	if entries, err := SearchEntries(query); err == nil {
		for _, e := range entries {
			createdAt, _ := e["CreatedAt"].(time.Time)
			typ, _ := e["Type"].(string)
			results = append(results, map[string]interface{}{
				"Kind":      "entry",
				"Title":     e["Title"],
				"Content":   e["Content"],
				"Role":      typ,
				"URL":       fmt.Sprintf("/entries/%d", e["ID"]),
				"CreatedAt": createdAt,
			})
		}
	}

	// IslamQA results
	if qaResults, err := SearchIslamQA(query); err == nil {
		for _, q := range qaResults {
			question, _ := q["Question"].(string)
			answer, _ := q["Answer"].(string)
			category, _ := q["Category"].(string)
			if len(answer) > 500 {
				answer = answer[:500] + "..."
			}
			results = append(results, map[string]interface{}{
				"Kind":    "islamqa",
				"Title":   question,
				"Content": answer,
				"Role":    category,
				"URL":     fmt.Sprintf("/islamqa/%d", q["ID"]),
			})
		}
	}

	// Searches results (cached Quran/Hadith/Names of Allah from reminder API)
	if remResults, err := SearchSearches(query); err == nil {
		for _, r := range remResults {
			question, _ := r["Question"].(string)
			answer, _ := r["Answer"].(string)
			if len(answer) > 500 {
				answer = answer[:500] + "..."
			}
			results = append(results, map[string]interface{}{
				"Kind":    "searches",
				"Title":   question,
				"Content": answer,
				"Role":    "quran/hadith",
				"URL":     "#",
			})
		}
	}

	// Quran verses
	if qResults, err := SearchQuran(query); err == nil {
		for _, q := range qResults {
			text, _ := q["Text"].(string)
			chapterName, _ := q["ChapterName"].(string)
			chapter, _ := q["Chapter"].(int)
			verse, _ := q["Verse"].(int)
			if len(text) > 500 {
				text = text[:500] + "..."
			}
			results = append(results, map[string]interface{}{
				"Kind":    "quran",
				"Title":   fmt.Sprintf("%s %d:%d", chapterName, chapter, verse),
				"Content": text,
				"Role":    "quran",
				"URL":     fmt.Sprintf("/quran/%d/%d", chapter, verse),
			})
		}
	}

	// Hadith results
	if hResults, err := SearchHadith(query); err == nil {
		for _, h := range hResults {
			text, _ := h["Text"].(string)
			book, _ := h["Book"].(string)
			narrator, _ := h["Narrator"].(string)
			if len(text) > 500 {
				text = text[:500] + "..."
			}
			title := book
			if narrator != "" {
				title = book + " — " + narrator
			}
			results = append(results, map[string]interface{}{
				"Kind":    "hadith",
				"Title":   title,
				"Content": text,
				"Role":    "hadith",
				"URL":     fmt.Sprintf("/hadith/%d", h["ID"]),
			})
		}
	}

	// Names of Allah results
	if nResults, err := SearchNames(query); err == nil {
		for _, n := range nResults {
			english, _ := n["English"].(string)
			meaning, _ := n["Meaning"].(string)
			desc, _ := n["Description"].(string)
			if len(desc) > 500 {
				desc = desc[:500] + "..."
			}
			results = append(results, map[string]interface{}{
				"Kind":    "names",
				"Title":   english + " — " + meaning,
				"Content": desc,
				"Role":    "names of allah",
				"URL":     fmt.Sprintf("/name/%d", n["ID"]),
			})
		}
	}

	// Ghazali results (Ihya Ulum al-Din — Revival of the Islamic Sciences)
	if gResults, err := SearchGhazali(query); err == nil {
		for _, g := range gResults {
			content, _ := g["Content"].(string)
			chapter, _ := g["Chapter"].(string)
			volumeTitle, _ := g["VolumeTitle"].(string)
			if len(content) > 500 {
				content = content[:500] + "..."
			}
			results = append(results, map[string]interface{}{
				"Kind":    "ghazali",
				"Title":   chapter,
				"Content": content,
				"Role":    volumeTitle,
				"URL":     fmt.Sprintf("/ghazali/%d", g["ID"]),
			})
		}
	}

	// Riyad us-Saliheen results
	if rResults, err := SearchRiyad(query); err == nil {
		for _, r := range rResults {
			text, _ := r["Text"].(string)
			book, _ := r["Book"].(string)
			narrator, _ := r["Narrator"].(string)
			if len(text) > 500 {
				text = text[:500] + "..."
			}
			title := book
			if narrator != "" {
				title = book + " — " + narrator
			}
			results = append(results, map[string]interface{}{
				"Kind":    "salihin",
				"Title":   title,
				"Content": text,
				"Role":    "hadith",
				"URL":     fmt.Sprintf("/salihin/%d", r["ID"]),
			})
		}
	}

	// Adhkar results (duas/dhikr)
	if aResults, err := SearchAdhkar(query); err == nil {
		for _, a := range aResults {
			translation, _ := a["Translation"].(string)
			category, _ := a["Category"].(string)
			title, _ := a["Title"].(string)
			if len(translation) > 500 {
				translation = translation[:500] + "..."
			}
			results = append(results, map[string]interface{}{
				"Kind":    "adhkar",
				"Title":   title,
				"Content": translation,
				"Role":    category,
				"URL":     fmt.Sprintf("/adhkar/%d", a["ID"]),
			})
		}
	}

	// Note items
	if items, err := SearchNotes(query, userID); err == nil {
		for _, n := range items {
			content := n.Content
			if len(content) > 500 {
				content = content[:500] + "..."
			}
			results = append(results, map[string]interface{}{
				"Kind":      "notes",
				"Title":     n.Title,
				"Content":   content,
				"Role":      "note",
				"URL":       fmt.Sprintf("/notes/edit/%d", n.ID),
				"CreatedAt": n.UpdatedAt,
			})
		}
	}

	// Sort newest first.
	sort.SliceStable(results, func(i, j int) bool {
		ti, _ := results[i]["CreatedAt"].(time.Time)
		tj, _ := results[j]["CreatedAt"].(time.Time)
		return ti.After(tj)
	})

	return results, nil
}

// Session functions

func GetSessionByToken(token string) *Session {
	var s Session
	err := DB.QueryRow(`
		SELECT token, email, name, created_at, expires_at 
		FROM sessions WHERE token = ? AND expires_at > CURRENT_TIMESTAMP
	`, token).Scan(&s.Token, &s.Email, &s.Name, &s.CreatedAt, &s.ExpiresAt)
	if err != nil {
		log.Printf("DB lookup error: %v", err)
		return nil
	}
	return &s
}

func CreateSession(email, name string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(b)

	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days
	_, err := DB.Exec(`
		INSERT INTO sessions (token, email, name, expires_at) VALUES (?, ?, ?, ?)
	`, token, email, name, expiresAt)
	if err != nil {
		return "", err
	}
	return token, nil
}

func DeleteSession(token string) {
	DB.Exec(`DELETE FROM sessions WHERE token = ?`, token)
}

// OAuth state functions

func CreateOAuthState(state string) error {
	expiresAt := time.Now().Add(10 * time.Minute)
	_, err := DB.Exec(`INSERT INTO oauth_states (state, expires_at) VALUES (?, ?)`, state, expiresAt)
	return err
}

func ValidateOAuthState(state string) bool {
	var s string
	err := DB.QueryRow(`SELECT state FROM oauth_states WHERE state = ? AND expires_at > CURRENT_TIMESTAMP`, state).Scan(&s)
	if err != nil {
		return false
	}
	DB.Exec(`DELETE FROM oauth_states WHERE state = ?`, state)
	return true
}

// Entry functions

func GetEntries(limit int) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT id, type, title, content, created_at 
		FROM entries 
		ORDER BY created_at DESC 
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []map[string]interface{}
	for rows.Next() {
		var id int64
		var typ, title string
		var content sql.NullString
		var createdAt time.Time
		rows.Scan(&id, &typ, &title, &content, &createdAt)
		entries = append(entries, map[string]interface{}{
			"ID":        id,
			"Type":      typ,
			"Title":     title,
			"Content":   content.String,
			"CreatedAt": createdAt,
		})
	}
	return entries, nil
}

func SaveEntry(entryType, title, content, metadata string) (int64, error) {
	result, err := DB.Exec(`
		INSERT INTO entries (type, title, content, metadata) VALUES (?, ?, ?, ?)
	`, entryType, title, content, metadata)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func GetEntryByTitle(entryType, title string) (map[string]interface{}, error) {
	var id int64
	var content, metadata sql.NullString
	var createdAt time.Time

	err := DB.QueryRow(`
		SELECT id, content, metadata, created_at FROM entries WHERE type = ? AND title = ?
	`, entryType, title).Scan(&id, &content, &metadata, &createdAt)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"ID":        id,
		"Type":      entryType,
		"Title":     title,
		"Content":   content.String,
		"Metadata":  metadata.String,
		"CreatedAt": createdAt,
	}, nil
}

func SearchEntries(query string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT e.id, e.type, e.title, e.content, e.created_at
		FROM entries e
		JOIN entries_fts fts ON e.id = fts.docid
		WHERE entries_fts MATCH ?
		ORDER BY e.created_at DESC
		LIMIT 10
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var typ, title string
		var content sql.NullString
		var createdAt time.Time
		rows.Scan(&id, &typ, &title, &content, &createdAt)

		c := content.String
		if len(c) > 500 {
			c = c[:500] + "..."
		}

		results = append(results, map[string]interface{}{
			"ID":        id,
			"Type":      typ,
			"Title":     title,
			"Content":   c,
			"CreatedAt": createdAt,
		})
	}
	return results, nil
}

func GetEntry(id int64) (map[string]interface{}, error) {
	var typ, title string
	var content, metadata sql.NullString
	var createdAt, updatedAt time.Time

	err := DB.QueryRow(`
		SELECT id, type, title, content, metadata, created_at, updated_at 
		FROM entries WHERE id = ?
	`, id).Scan(&id, &typ, &title, &content, &metadata, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"ID":        id,
		"Type":      typ,
		"Title":     title,
		"Content":   content.String,
		"Metadata":  metadata.String,
		"CreatedAt": createdAt,
		"UpdatedAt": updatedAt,
	}, nil
}

// Email functions

type EmailThread struct {
	ID             int64
	ThreadID       string
	ConversationID int64
	LastMessageID  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type EmailLog struct {
	ID          int64
	MessageID   string
	ThreadID    string
	Direction   string
	FromEmail   string
	ToEmail     string
	Subject     string
	Body        string
	Status      string
	Error       string
	CreatedAt   time.Time
	ProcessedAt *time.Time
}

func GetEmailThread(threadID string) (*EmailThread, error) {
	var t EmailThread
	var lastMsgID sql.NullString
	err := DB.QueryRow(`
		SELECT id, thread_id, conversation_id, last_message_id, created_at, updated_at
		FROM email_threads WHERE thread_id = ?
	`, threadID).Scan(&t.ID, &t.ThreadID, &t.ConversationID, &lastMsgID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	t.LastMessageID = lastMsgID.String
	return &t, nil
}

// GetEmailThreadByMessageID looks up a thread by any message ID in the thread
func GetEmailThreadByMessageID(messageID string) (*EmailThread, error) {
	var t EmailThread
	var lastMsgID sql.NullString
	// Look up by thread_id (which is the first message's ID) or last_message_id
	err := DB.QueryRow(`
		SELECT id, thread_id, conversation_id, last_message_id, created_at, updated_at
		FROM email_threads WHERE thread_id = ? OR last_message_id = ?
	`, messageID, messageID).Scan(&t.ID, &t.ThreadID, &t.ConversationID, &lastMsgID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	t.LastMessageID = lastMsgID.String
	return &t, nil
}

func CreateEmailThread(threadID string, conversationID int64, lastMessageID string) error {
	_, err := DB.Exec(`
		INSERT INTO email_threads (thread_id, conversation_id, last_message_id)
		VALUES (?, ?, ?)
	`, threadID, conversationID, lastMessageID)
	return err
}

func UpdateEmailThread(threadID, lastMessageID string) error {
	_, err := DB.Exec(`
		UPDATE email_threads SET last_message_id = ?, updated_at = CURRENT_TIMESTAMP
		WHERE thread_id = ?
	`, lastMessageID, threadID)
	return err
}

func LogEmail(messageID, threadID, direction, from, to, subject, body, status string) (int64, error) {
	result, err := DB.Exec(`
		INSERT INTO email_log (message_id, thread_id, direction, from_email, to_email, subject, body, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, messageID, threadID, direction, from, to, subject, body, status)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func UpdateEmailStatus(id int64, status, errMsg string) error {
	if status == "processed" {
		_, err := DB.Exec(`
			UPDATE email_log SET status = ?, processed_at = CURRENT_TIMESTAMP WHERE id = ?
		`, status, id)
		return err
	}
	_, err := DB.Exec(`
		UPDATE email_log SET status = ?, error = ?, processed_at = CURRENT_TIMESTAMP WHERE id = ?
	`, status, errMsg, id)
	return err
}

func GetPendingEmails() ([]EmailLog, error) {
	rows, err := DB.Query(`
		SELECT id, message_id, thread_id, direction, from_email, to_email, subject, body, status, created_at
		FROM email_log WHERE status = 'pending' ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []EmailLog
	for rows.Next() {
		var e EmailLog
		var msgID, threadID sql.NullString
		rows.Scan(&e.ID, &msgID, &threadID, &e.Direction, &e.FromEmail, &e.ToEmail, &e.Subject, &e.Body, &e.Status, &e.CreatedAt)
		e.MessageID = msgID.String
		e.ThreadID = threadID.String
		emails = append(emails, e)
	}
	return emails, nil
}

func EmailExists(messageID string) bool {
	var id int64
	err := DB.QueryRow(`SELECT id FROM email_log WHERE message_id = ?`, messageID).Scan(&id)
	return err == nil
}

func UpdateEmailStatusByMessageID(messageID, status, errMsg string) error {
	if status == "processed" {
		_, err := DB.Exec(`
			UPDATE email_log SET status = ?, processed_at = CURRENT_TIMESTAMP WHERE message_id = ?
		`, status, messageID)
		return err
	}
	_, err := DB.Exec(`
		UPDATE email_log SET status = ?, error = ?, processed_at = CURRENT_TIMESTAMP WHERE message_id = ?
	`, status, errMsg, messageID)
	return err
}

// Pending task functions

type PendingTask struct {
	ID             int64
	Channel        string
	ConversationID int64
	ReferenceID    string // Channel-specific ref (e.g., email message ID)
	Status         string
	Attempts       int
	MaxAttempts    int
	LastError      string
	Metadata       string // JSON for channel-specific data
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func CreatePendingTask(channel string, conversationID int64, referenceID, metadata string) (int64, error) {
	result, err := DB.Exec(`
		INSERT INTO pending_tasks (channel, conversation_id, reference_id, metadata)
		VALUES (?, ?, ?, ?)
	`, channel, conversationID, referenceID, metadata)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func GetPendingTasks() ([]PendingTask, error) {
	rows, err := DB.Query(`
		SELECT id, channel, conversation_id, reference_id, status, attempts, max_attempts, last_error, metadata, created_at, updated_at
		FROM pending_tasks 
		WHERE status IN ('pending', 'processing') AND attempts < max_attempts
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []PendingTask
	for rows.Next() {
		var t PendingTask
		var refID, lastErr, meta sql.NullString
		err := rows.Scan(&t.ID, &t.Channel, &t.ConversationID, &refID, &t.Status, &t.Attempts, &t.MaxAttempts, &lastErr, &meta, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			continue
		}
		t.ReferenceID = refID.String
		t.LastError = lastErr.String
		t.Metadata = meta.String
		tasks = append(tasks, t)
	}
	return tasks, nil
}

func UpdateTaskStatus(id int64, status, lastError string) error {
	_, err := DB.Exec(`
		UPDATE pending_tasks 
		SET status = ?, last_error = ?, attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP 
		WHERE id = ?
	`, status, lastError, id)
	return err
}

func MarkTaskProcessing(id int64) error {
	_, err := DB.Exec(`
		UPDATE pending_tasks SET status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, id)
	return err
}

func MarkTaskCompleted(id int64) error {
	_, err := DB.Exec(`
		UPDATE pending_tasks SET status = 'completed', attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, id)
	return err
}

func MarkTaskFailed(id int64, errMsg string) error {
	_, err := DB.Exec(`
		UPDATE pending_tasks SET status = 'failed', last_error = ?, attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, errMsg, id)
	return err
}

// ResetStaleTasks marks any 'processing' tasks as 'pending' (for restart recovery)
func ResetStaleTasks() error {
	_, err := DB.Exec(`
		UPDATE pending_tasks SET status = 'pending', updated_at = CURRENT_TIMESTAMP 
		WHERE status = 'processing'
	`)
	return err
}

// Account/credential functions for estate planning

type Account struct {
	ID          int64
	Service     string
	AccountID   string
	Password    string
	APIKey      string
	Description string
	URL         string
	EnvVar      string
	Notes       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func GetAccounts() ([]Account, error) {
	rows, err := DB.Query(`
		SELECT id, service, account_id, password, api_key, description, url, env_var, notes, created_at, updated_at
		FROM accounts ORDER BY service
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []Account
	for rows.Next() {
		var a Account
		var accountID, password, apiKey, desc, url, envVar, notes sql.NullString
		err := rows.Scan(&a.ID, &a.Service, &accountID, &password, &apiKey, &desc, &url, &envVar, &notes, &a.CreatedAt, &a.UpdatedAt)
		if err != nil {
			continue
		}
		a.AccountID = accountID.String
		a.Password = password.String
		a.APIKey = apiKey.String
		a.Description = desc.String
		a.URL = url.String
		a.EnvVar = envVar.String
		a.Notes = notes.String
		accounts = append(accounts, a)
	}
	return accounts, nil
}

func SaveAccount(service, accountID, password, apiKey, description, url, envVar, notes string) (int64, error) {
	result, err := DB.Exec(`
		INSERT INTO accounts (service, account_id, password, api_key, description, url, env_var, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, service, accountID, password, apiKey, description, url, envVar, notes)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func UpdateAccount(id int64, service, accountID, password, apiKey, description, url, envVar, notes string) error {
	_, err := DB.Exec(`
		UPDATE accounts SET service=?, account_id=?, password=?, api_key=?, description=?, url=?, env_var=?, notes=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?
	`, service, accountID, password, apiKey, description, url, envVar, notes, id)
	return err
}

func DeleteAccount(id int64) error {
	_, err := DB.Exec(`DELETE FROM accounts WHERE id = ?`, id)
	return err
}

// User functions

type User struct {
	ID           int64
	Email        string
	Name         string
	Role         string
	AddedBy      string
	PasswordHash string
	Picture      string
	Latitude     float64
	Longitude    float64
	Timezone     string
	CreatedAt    time.Time
}

func GetUsers() ([]User, error) {
	rows, err := DB.Query(`SELECT id, email, name, role, added_by, password_hash, picture, created_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var name, addedBy, passwordHash, picture sql.NullString
		err := rows.Scan(&u.ID, &u.Email, &name, &u.Role, &addedBy, &passwordHash, &picture, &u.CreatedAt)
		if err != nil {
			continue
		}
		u.Name = name.String
		u.AddedBy = addedBy.String
		u.PasswordHash = passwordHash.String
		u.Picture = picture.String
		users = append(users, u)
	}
	return users, nil
}

func AddUser(email, name, role, addedBy string) error {
	_, err := DB.Exec(`INSERT INTO users (email, name, role, added_by) VALUES (?, ?, ?, ?)`,
		email, name, role, addedBy)
	return err
}

func RemoveUser(id int64) error {
	_, err := DB.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

func IsAdmin(email string) bool {
	var id int64
	err := DB.QueryRow(`SELECT id FROM users WHERE email = ? AND role = 'admin'`, email).Scan(&id)
	return err == nil
}

func IsUser(email string) bool {
	var id int64
	err := DB.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&id)
	return err == nil
}

func UserCount() int {
	var count int
	DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count
}

func scanUser(row interface{ Scan(...interface{}) error }) (*User, error) {
	var u User
	var name, addedBy, passwordHash, picture, tz sql.NullString
	var lat, lng sql.NullFloat64
	err := row.Scan(&u.ID, &u.Email, &name, &u.Role, &addedBy, &passwordHash, &picture, &lat, &lng, &tz, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.Name = name.String
	u.AddedBy = addedBy.String
	u.PasswordHash = passwordHash.String
	u.Picture = picture.String
	u.Latitude = lat.Float64
	u.Longitude = lng.Float64
	u.Timezone = tz.String
	return &u, nil
}

func GetUserByEmail(email string) (*User, error) {
	return scanUser(DB.QueryRow(`SELECT id, email, name, role, added_by, password_hash, picture, latitude, longitude, timezone, created_at FROM users WHERE email = ?`, email))
}

func GetUserByID(id int64) (*User, error) {
	return scanUser(DB.QueryRow(`SELECT id, email, name, role, added_by, password_hash, picture, latitude, longitude, timezone, created_at FROM users WHERE id = ?`, id))
}

func SetUserPassword(id int64, hash string) error {
	_, err := DB.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	return err
}

func CreateUserWithPassword(email, name, passwordHash, role string) error {
	_, err := DB.Exec(`INSERT INTO users (email, name, password_hash, role, added_by) VALUES (?, ?, ?, ?, 'signup')`,
		email, name, passwordHash, role)
	return err
}

func UpdateUserProfile(email, name, picture string) error {
	_, err := DB.Exec(`UPDATE users SET name = ?, picture = ? WHERE email = ?`, name, picture, email)
	return err
}

func UpdateUserPicture(email, picture string) error {
	_, err := DB.Exec(`UPDATE users SET picture = ? WHERE email = ?`, picture, email)
	return err
}

func UpdateUserLocation(email string, lat, lng float64, timezone string) error {
	_, err := DB.Exec(`UPDATE users SET latitude = ?, longitude = ?, timezone = ? WHERE email = ?`, lat, lng, timezone, email)
	return err
}

// Settings functions

func GetSetting(key string) string {
	var value sql.NullString
	DB.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	return value.String
}

func SetSetting(key, value string) error {
	_, err := DB.Exec(`
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP
	`, key, value, value)
	return err
}

func GetSettingBool(key string) bool {
	return GetSetting(key) == "true"
}

func SetSettingBool(key string, value bool) error {
	if value {
		return SetSetting(key, "true")
	}
	return SetSetting(key, "false")
}

// Status/stats functions

type TaskStats struct {
	Pending   int
	Processing int
	Completed int
	Failed    int
}

func GetTaskStats() TaskStats {
	var stats TaskStats
	DB.QueryRow(`SELECT COUNT(*) FROM pending_tasks WHERE status = 'pending'`).Scan(&stats.Pending)
	DB.QueryRow(`SELECT COUNT(*) FROM pending_tasks WHERE status = 'processing'`).Scan(&stats.Processing)
	DB.QueryRow(`SELECT COUNT(*) FROM pending_tasks WHERE status = 'completed'`).Scan(&stats.Completed)
	DB.QueryRow(`SELECT COUNT(*) FROM pending_tasks WHERE status = 'failed'`).Scan(&stats.Failed)
	return stats
}

type EmailStats struct {
	Inbound   int
	Outbound  int
	Pending   int
	Failed    int
}

func GetEmailStats() EmailStats {
	var stats EmailStats
	DB.QueryRow(`SELECT COUNT(*) FROM email_log WHERE direction = 'inbound'`).Scan(&stats.Inbound)
	DB.QueryRow(`SELECT COUNT(*) FROM email_log WHERE direction = 'outbound'`).Scan(&stats.Outbound)
	DB.QueryRow(`SELECT COUNT(*) FROM email_log WHERE status = 'pending'`).Scan(&stats.Pending)
	DB.QueryRow(`SELECT COUNT(*) FROM email_log WHERE status = 'failed'`).Scan(&stats.Failed)
	return stats
}

func GetRecentEmails(limit int) ([]EmailLog, error) {
	rows, err := DB.Query(`
		SELECT id, message_id, thread_id, direction, from_email, to_email, subject, body, status, created_at
		FROM email_log ORDER BY created_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []EmailLog
	for rows.Next() {
		var e EmailLog
		var msgID, threadID, body sql.NullString
		err := rows.Scan(&e.ID, &msgID, &threadID, &e.Direction, &e.FromEmail, &e.ToEmail, &e.Subject, &body, &e.Status, &e.CreatedAt)
		if err != nil {
			continue
		}
		e.MessageID = msgID.String
		e.ThreadID = threadID.String
		e.Body = body.String
		emails = append(emails, e)
	}
	return emails, nil
}

func GetRecentTasks(limit int) ([]PendingTask, error) {
	rows, err := DB.Query(`
		SELECT id, channel, conversation_id, reference_id, status, attempts, max_attempts, last_error, metadata, created_at, updated_at
		FROM pending_tasks ORDER BY created_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []PendingTask
	for rows.Next() {
		var t PendingTask
		var refID, lastErr, meta sql.NullString
		err := rows.Scan(&t.ID, &t.Channel, &t.ConversationID, &refID, &t.Status, &t.Attempts, &t.MaxAttempts, &lastErr, &meta, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			continue
		}
		t.ReferenceID = refID.String
		t.LastError = lastErr.String
		t.Metadata = meta.String
		tasks = append(tasks, t)
	}
	return tasks, nil
}

// Note functions

type NoteItem struct {
	ID        int64
	Title     string
	Content   string
	UserID    int64
	Public    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

func GetNoteItems(userID int64, mineOnly bool) ([]NoteItem, error) {
	var query string
	var args []interface{}
	if mineOnly {
		query = `SELECT id, title, content, COALESCE(user_id, 0), COALESCE(public, 0), created_at, updated_at
			FROM notes_v2 WHERE user_id = ? ORDER BY updated_at DESC`
		args = []interface{}{userID}
	} else {
		query = `SELECT id, title, content, COALESCE(user_id, 0), COALESCE(public, 0), created_at, updated_at
			FROM notes_v2 WHERE user_id = ? OR public = 1 OR user_id IS NULL ORDER BY updated_at DESC`
		args = []interface{}{userID}
	}
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []NoteItem
	for rows.Next() {
		var v NoteItem
		var content sql.NullString
		var pub int
		err := rows.Scan(&v.ID, &v.Title, &content, &v.UserID, &pub, &v.CreatedAt, &v.UpdatedAt)
		if err != nil {
			continue
		}
		v.Content = content.String
		v.Public = pub == 1
		items = append(items, v)
	}
	return items, nil
}

func GetNoteItem(id int64) (*NoteItem, error) {
	var v NoteItem
	var content sql.NullString
	var pub int
	err := DB.QueryRow(`
		SELECT id, title, content, COALESCE(user_id, 0), COALESCE(public, 0), created_at, updated_at
		FROM notes_v2 WHERE id = ?
	`, id).Scan(&v.ID, &v.Title, &content, &v.UserID, &pub, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return nil, err
	}
	v.Content = content.String
	v.Public = pub == 1
	return &v, nil
}

func AddNoteItem(title, content string, userID int64) (int64, error) {
	result, err := DB.Exec(`
		INSERT INTO notes_v2 (title, content, user_id) VALUES (?, ?, ?)
	`, title, content, userID)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func UpdateNoteItem(id int64, title, content string) error {
	_, err := DB.Exec(`
		UPDATE notes_v2 SET title=?, content=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
	`, title, content, id)
	return err
}

func DeleteNoteItem(id int64) error {
	_, err := DB.Exec(`DELETE FROM notes_v2 WHERE id = ?`, id)
	return err
}

func SearchNotes(query string, userID int64) ([]NoteItem, error) {
	rows, err := DB.Query(`
		SELECT n.id, n.title, n.content, COALESCE(n.user_id, 0), COALESCE(n.public, 0), n.created_at, n.updated_at
		FROM notes_v2 n
		JOIN notes_fts fts ON n.id = fts.docid
		WHERE notes_fts MATCH ?
		AND (n.user_id = ? OR n.public = 1 OR n.user_id IS NULL)
		LIMIT 20
	`, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []NoteItem
	for rows.Next() {
		var v NoteItem
		var content sql.NullString
		var pub int
		err := rows.Scan(&v.ID, &v.Title, &content, &v.UserID, &pub, &v.CreatedAt, &v.UpdatedAt)
		if err != nil {
			continue
		}
		v.Content = content.String
		v.Public = pub == 1
		items = append(items, v)
	}
	return items, nil
}

// Toggle and ownership functions

func ToggleConversationPublic(id int64, public bool) error {
	val := 0
	if public {
		val = 1
	}
	_, err := DB.Exec(`UPDATE conversations SET public = ? WHERE id = ?`, val, id)
	return err
}

func ToggleNotePublic(id int64, public bool) error {
	val := 0
	if public {
		val = 1
	}
	_, err := DB.Exec(`UPDATE notes_v2 SET public = ? WHERE id = ?`, val, id)
	return err
}

func GetConversationOwner(id int64) int64 {
	var userID sql.NullInt64
	DB.QueryRow(`SELECT user_id FROM conversations WHERE id = ?`, id).Scan(&userID)
	if userID.Valid {
		return userID.Int64
	}
	return 0
}

func GetNoteOwner(id int64) int64 {
	var userID sql.NullInt64
	DB.QueryRow(`SELECT user_id FROM notes_v2 WHERE id = ?`, id).Scan(&userID)
	if userID.Valid {
		return userID.Int64
	}
	return 0
}

func GetUserID(email string) int64 {
	var id int64
	DB.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&id)
	return id
}

// IslamQA functions

func ClearIslamQA() {
	DB.Exec(`DELETE FROM islamqa`)
	DB.Exec(`DELETE FROM islamqa_fts`)
}

func InsertSearch(question, answer string) error {
	_, err := DB.Exec(`INSERT INTO searches (question, answer) VALUES (?, ?)`, question, answer)
	return err
}

func SearchSearches(query string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT s.id, s.question, s.answer
		FROM searches s
		JOIN searches_fts fts ON s.id = fts.docid
		WHERE searches_fts MATCH ?
		LIMIT 10
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var question, answer string
		rows.Scan(&id, &question, &answer)
		results = append(results, map[string]interface{}{
			"ID":       id,
			"Question": question,
			"Answer":   answer,
		})
	}
	return results, nil
}

func IslamQACount() int {
	var count int
	DB.QueryRow(`SELECT COUNT(*) FROM islamqa`).Scan(&count)
	return count
}

func InsertIslamQA(category, question, answer string) error {
	_, err := DB.Exec(`INSERT INTO islamqa (category, question, answer) VALUES (?, ?, ?)`,
		category, question, answer)
	return err
}

func SearchIslamQA(query string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT i.id, i.category, i.question, i.answer
		FROM islamqa i
		JOIN islamqa_fts fts ON i.id = fts.docid
		WHERE islamqa_fts MATCH ?
		LIMIT 10
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var category, question, answer string
		rows.Scan(&id, &category, &question, &answer)
		results = append(results, map[string]interface{}{
			"ID":       id,
			"Category": category,
			"Question": question,
			"Answer":   answer,
		})
	}
	return results, nil
}

func GetIslamQA(id int64) (map[string]interface{}, error) {
	var category, question, answer string
	err := DB.QueryRow(`SELECT id, category, question, answer FROM islamqa WHERE id = ?`, id).Scan(&id, &category, &question, &answer)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ID":       id,
		"Category": category,
		"Question": question,
		"Answer":   answer,
	}, nil
}

// Reminder content functions (daily feed from reminder.dev)

func SaveReminderContent(verse, hadith, nameOfAllah, message, verseLink, hadithLink, nameLink string) error {
	_, err := DB.Exec(`
		INSERT INTO reminder_content (verse, hadith, name_of_allah, message, verse_link, hadith_link, name_link)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, verse, hadith, nameOfAllah, message, verseLink, hadithLink, nameLink)
	return err
}

func GetLatestReminderContent() (map[string]interface{}, error) {
	var id int64
	var verse, hadith, nameOfAllah, message, verseLink, hadithLink, nameLink sql.NullString
	var fetchedAt time.Time

	err := DB.QueryRow(`
		SELECT id, verse, hadith, name_of_allah, message, verse_link, hadith_link, name_link, fetched_at
		FROM reminder_content ORDER BY fetched_at DESC LIMIT 1
	`).Scan(&id, &verse, &hadith, &nameOfAllah, &message, &verseLink, &hadithLink, &nameLink, &fetchedAt)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"ID":          id,
		"Verse":       verse.String,
		"Hadith":      hadith.String,
		"NameOfAllah": nameOfAllah.String,
		"Message":     message.String,
		"VerseLink":   verseLink.String,
		"HadithLink":  hadithLink.String,
		"NameLink":    nameLink.String,
		"FetchedAt":   fetchedAt,
	}, nil
}

func GetRandomIslamQA() (map[string]interface{}, error) {
	var id int64
	var category, question, answer string
	err := DB.QueryRow(`SELECT id, category, question, answer FROM islamqa ORDER BY RANDOM() LIMIT 1`).Scan(&id, &category, &question, &answer)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ID":       id,
		"Category": category,
		"Question": question,
		"Answer":   answer,
	}, nil
}

// Ghazali functions

func GhazaliCount() int {
	var count int
	DB.QueryRow(`SELECT COUNT(*) FROM ghazali`).Scan(&count)
	return count
}

func ClearGhazali() {
	DB.Exec(`DELETE FROM ghazali`)
	DB.Exec(`DELETE FROM ghazali_fts`)
}

func InsertGhazali(volume int, volumeTitle, chapter string, part int, content string) error {
	_, err := DB.Exec(`INSERT INTO ghazali (volume, volume_title, chapter, part, content) VALUES (?, ?, ?, ?, ?)`,
		volume, volumeTitle, chapter, part, content)
	return err
}

func SearchGhazali(query string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT g.id, g.volume, g.volume_title, g.chapter, g.part, g.content
		FROM ghazali g
		JOIN ghazali_fts fts ON g.id = fts.docid
		WHERE ghazali_fts MATCH ?
		LIMIT 10
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var volume, part int
		var volumeTitle, chapter, content string
		rows.Scan(&id, &volume, &volumeTitle, &chapter, &part, &content)
		results = append(results, map[string]interface{}{
			"ID":          id,
			"Volume":      volume,
			"VolumeTitle": volumeTitle,
			"Chapter":     chapter,
			"Part":        part,
			"Content":     content,
		})
	}
	return results, nil
}

func GetGhazali(id int64) (map[string]interface{}, error) {
	var volume, part int
	var volumeTitle, chapter, content string
	err := DB.QueryRow(`SELECT id, volume, volume_title, chapter, part, content FROM ghazali WHERE id = ?`, id).Scan(
		&id, &volume, &volumeTitle, &chapter, &part, &content)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ID":          id,
		"Volume":      volume,
		"VolumeTitle": volumeTitle,
		"Chapter":     chapter,
		"Part":        part,
		"Content":     content,
	}, nil
}

// Quran functions

func QuranCount() int {
	var count int
	DB.QueryRow(`SELECT COUNT(*) FROM quran`).Scan(&count)
	return count
}

func ClearQuran() {
	DB.Exec(`DELETE FROM quran`)
	DB.Exec(`DELETE FROM quran_fts`)
}

func InsertQuranVerse(chapter int, chapterName string, verse int, text, arabic, commentary string) error {
	_, err := DB.Exec(`INSERT INTO quran (chapter, chapter_name, verse, text, arabic, commentary) VALUES (?, ?, ?, ?, ?, ?)`,
		chapter, chapterName, verse, text, arabic, commentary)
	return err
}

func SearchQuran(query string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT q.id, q.chapter, q.chapter_name, q.verse, q.text, q.arabic, q.commentary
		FROM quran q
		JOIN quran_fts fts ON q.id = fts.docid
		WHERE quran_fts MATCH ?
		LIMIT 10
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var chapter, verse int
		var chapterName, text string
		var arabic, commentary sql.NullString
		rows.Scan(&id, &chapter, &chapterName, &verse, &text, &arabic, &commentary)
		results = append(results, map[string]interface{}{
			"ID":          id,
			"Chapter":     chapter,
			"ChapterName": chapterName,
			"Verse":       verse,
			"Text":        text,
			"Arabic":      arabic.String,
			"Commentary":  commentary.String,
		})
	}
	return results, nil
}

func GetQuranVerse(chapter, verse int) (map[string]interface{}, error) {
	var id int64
	var chapterName, text string
	var arabic, commentary sql.NullString
	err := DB.QueryRow(`SELECT id, chapter_name, text, arabic, commentary FROM quran WHERE chapter = ? AND verse = ?`,
		chapter, verse).Scan(&id, &chapterName, &text, &arabic, &commentary)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ID":          id,
		"Chapter":     chapter,
		"ChapterName": chapterName,
		"Verse":       verse,
		"Text":        text,
		"Arabic":      arabic.String,
		"Commentary":  commentary.String,
	}, nil
}

// Hadith functions

func HadithCount() int {
	var count int
	DB.QueryRow(`SELECT COUNT(*) FROM hadith`).Scan(&count)
	return count
}

func ClearHadith() {
	DB.Exec(`DELETE FROM hadith`)
	DB.Exec(`DELETE FROM hadith_fts`)
}

func InsertHadith(book string, number int, narrator, text, arabic string) error {
	_, err := DB.Exec(`INSERT INTO hadith (book, number, narrator, text, arabic) VALUES (?, ?, ?, ?, ?)`,
		book, number, narrator, text, arabic)
	return err
}

func SearchHadith(query string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT h.id, h.book, h.number, h.narrator, h.text, h.arabic
		FROM hadith h
		JOIN hadith_fts fts ON h.id = fts.docid
		WHERE hadith_fts MATCH ?
		LIMIT 10
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var number int
		var book, text string
		var narrator, arabic sql.NullString
		rows.Scan(&id, &book, &number, &narrator, &text, &arabic)
		results = append(results, map[string]interface{}{
			"ID":       id,
			"Book":     book,
			"Number":   number,
			"Narrator": narrator.String,
			"Text":     text,
			"Arabic":   arabic.String,
		})
	}
	return results, nil
}

func GetHadith(id int64) (map[string]interface{}, error) {
	var number int
	var book, text string
	var narrator, arabic sql.NullString
	err := DB.QueryRow(`SELECT id, book, number, narrator, text, arabic FROM hadith WHERE id = ?`, id).Scan(
		&id, &book, &number, &narrator, &text, &arabic)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ID":       id,
		"Book":     book,
		"Number":   number,
		"Narrator": narrator.String,
		"Text":     text,
		"Arabic":   arabic.String,
	}, nil
}

// Names of Allah functions

func NamesCount() int {
	var count int
	DB.QueryRow(`SELECT COUNT(*) FROM names`).Scan(&count)
	return count
}

func ClearNames() {
	DB.Exec(`DELETE FROM names`)
	DB.Exec(`DELETE FROM names_fts`)
}

func RebuildSourcesFTS() {
	DB.Exec(`DELETE FROM quran_fts`)
	DB.Exec(`INSERT INTO quran_fts(docid, text, commentary) SELECT id, text, commentary FROM quran`)
	DB.Exec(`DELETE FROM hadith_fts`)
	DB.Exec(`INSERT INTO hadith_fts(docid, text, narrator) SELECT id, text, narrator FROM hadith`)
	DB.Exec(`DELETE FROM names_fts`)
	DB.Exec(`INSERT INTO names_fts(docid, english, meaning, description, summary) SELECT id, english, meaning, description, summary FROM names`)
	log.Println("Rebuilt FTS indexes for quran, hadith, names")
}

func InsertName(number int, english, arabic, meaning, description, summary string) error {
	_, err := DB.Exec(`INSERT INTO names (number, english, arabic, meaning, description, summary) VALUES (?, ?, ?, ?, ?, ?)`,
		number, english, arabic, meaning, description, summary)
	return err
}

func SearchNames(query string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT n.id, n.number, n.english, n.arabic, n.meaning, n.description, n.summary
		FROM names n
		JOIN names_fts fts ON n.id = fts.docid
		WHERE names_fts MATCH ?
		LIMIT 10
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var number int
		var english string
		var arabic, meaning, description, summary sql.NullString
		rows.Scan(&id, &number, &english, &arabic, &meaning, &description, &summary)
		results = append(results, map[string]interface{}{
			"ID":          id,
			"Number":      number,
			"English":     english,
			"Arabic":      arabic.String,
			"Meaning":     meaning.String,
			"Description": description.String,
			"Summary":     summary.String,
		})
	}
	return results, nil
}

func GetName(id int64) (map[string]interface{}, error) {
	var number int
	var english string
	var arabic, meaning, description, summary sql.NullString
	err := DB.QueryRow(`SELECT id, number, english, arabic, meaning, description, summary FROM names WHERE id = ?`, id).Scan(
		&id, &number, &english, &arabic, &meaning, &description, &summary)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ID":          id,
		"Number":      number,
		"English":     english,
		"Arabic":      arabic.String,
		"Meaning":     meaning.String,
		"Description": description.String,
		"Summary":     summary.String,
	}, nil
}

// IslamQA index functions

func GetIslamQACategories() ([]map[string]interface{}, error) {
	rows, err := DB.Query(`SELECT category, COUNT(*) as count FROM islamqa GROUP BY category ORDER BY category`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var category string
		var count int
		rows.Scan(&category, &count)
		results = append(results, map[string]interface{}{
			"Category": category,
			"Count":    count,
		})
	}
	return results, nil
}

func GetIslamQAByCategory(category string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`SELECT id, category, question FROM islamqa WHERE category = ? ORDER BY id`, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var cat, question string
		rows.Scan(&id, &cat, &question)
		results = append(results, map[string]interface{}{
			"ID":       id,
			"Category": cat,
			"Question": question,
		})
	}
	return results, nil
}

func GetAllIslamQA() ([]map[string]interface{}, error) {
	rows, err := DB.Query(`SELECT id, category, question FROM islamqa ORDER BY category, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var category, question string
		rows.Scan(&id, &category, &question)
		results = append(results, map[string]interface{}{
			"ID":       id,
			"Category": category,
			"Question": question,
		})
	}
	return results, nil
}

func GetIslamQAPrevNext(id int64) (prevID, nextID int64) {
	DB.QueryRow(`SELECT id FROM islamqa WHERE id < ? ORDER BY id DESC LIMIT 1`, id).Scan(&prevID)
	DB.QueryRow(`SELECT id FROM islamqa WHERE id > ? ORDER BY id ASC LIMIT 1`, id).Scan(&nextID)
	return
}

// Ghazali index functions

func romanToInt(s string) int {
	roman := map[byte]int{'I': 1, 'V': 5, 'X': 10, 'L': 50}
	total := 0
	for i := 0; i < len(s); i++ {
		v := roman[s[i]]
		if i+1 < len(s) && roman[s[i+1]] > v {
			total -= v
		} else {
			total += v
		}
	}
	return total
}

func chapterSortKey(chapter string) int {
	// Extract Roman numeral from "Chapter IX: ..."
	parts := strings.SplitN(chapter, ":", 2)
	if len(parts) > 0 {
		num := strings.TrimPrefix(parts[0], "Chapter ")
		return romanToInt(strings.TrimSpace(num))
	}
	return 0
}

func GetGhazaliChapters() ([]map[string]interface{}, error) {
	rows, err := DB.Query(`SELECT volume, volume_title, chapter, MIN(id) as first_id FROM ghazali GROUP BY volume, chapter`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var volume int
		var volumeTitle, chapter string
		var firstID int64
		rows.Scan(&volume, &volumeTitle, &chapter, &firstID)
		results = append(results, map[string]interface{}{
			"Volume":      volume,
			"VolumeTitle": volumeTitle,
			"Chapter":     chapter,
			"FirstID":     firstID,
		})
	}
	sort.SliceStable(results, func(i, j int) bool {
		vi := results[i]["Volume"].(int)
		vj := results[j]["Volume"].(int)
		if vi != vj {
			return vi < vj
		}
		return chapterSortKey(results[i]["Chapter"].(string)) < chapterSortKey(results[j]["Chapter"].(string))
	})
	return results, nil
}

func GetGhazaliByVolume(volume int) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`SELECT DISTINCT volume, volume_title, chapter, MIN(id) as first_id FROM ghazali WHERE volume = ? GROUP BY chapter ORDER BY chapter`, volume)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var vol int
		var volumeTitle, chapter string
		var firstID int64
		rows.Scan(&vol, &volumeTitle, &chapter, &firstID)
		results = append(results, map[string]interface{}{
			"Volume":      vol,
			"VolumeTitle": volumeTitle,
			"Chapter":     chapter,
			"FirstID":     firstID,
		})
	}
	sort.SliceStable(results, func(i, j int) bool {
		return chapterSortKey(results[i]["Chapter"].(string)) < chapterSortKey(results[j]["Chapter"].(string))
	})
	return results, nil
}

func GetGhazaliPrevNext(id int64) (prevID, nextID int64) {
	DB.QueryRow(`SELECT id FROM ghazali WHERE id < ? ORDER BY id DESC LIMIT 1`, id).Scan(&prevID)
	DB.QueryRow(`SELECT id FROM ghazali WHERE id > ? ORDER BY id ASC LIMIT 1`, id).Scan(&nextID)
	return
}

// Adhkar functions

func AdhkarCount() int {
	var count int
	DB.QueryRow(`SELECT COUNT(*) FROM adhkar`).Scan(&count)
	return count
}

func ClearAdhkar() {
	DB.Exec(`DELETE FROM adhkar`)
	DB.Exec(`DELETE FROM adhkar_fts`)
}

func InsertAdhkar(category, title, arabic, transliteration, translation, notes, benefits, source string) error {
	_, err := DB.Exec(`INSERT INTO adhkar (category, title, arabic, transliteration, translation, notes, benefits, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		category, title, arabic, transliteration, translation, notes, benefits, source)
	return err
}

func SearchAdhkar(query string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT a.id, a.category, a.title, a.arabic, a.transliteration, a.translation, a.notes, a.benefits, a.source
		FROM adhkar a
		JOIN adhkar_fts fts ON a.id = fts.docid
		WHERE adhkar_fts MATCH ?
		LIMIT 10
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var category, title string
		var arabic, transliteration, translation, notes, benefits, source sql.NullString
		rows.Scan(&id, &category, &title, &arabic, &transliteration, &translation, &notes, &benefits, &source)
		results = append(results, map[string]interface{}{
			"ID":              id,
			"Category":        category,
			"Title":           title,
			"Arabic":          arabic.String,
			"Transliteration": transliteration.String,
			"Translation":     translation.String,
			"Notes":           notes.String,
			"Benefits":        benefits.String,
			"Source":          source.String,
		})
	}
	return results, nil
}

func GetAdhkar(id int64) (map[string]interface{}, error) {
	var category, title string
	var arabic, transliteration, translation, notes, benefits, source sql.NullString
	err := DB.QueryRow(`SELECT id, category, title, arabic, transliteration, translation, notes, benefits, source FROM adhkar WHERE id = ?`, id).Scan(
		&id, &category, &title, &arabic, &transliteration, &translation, &notes, &benefits, &source)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ID":              id,
		"Category":        category,
		"Title":           title,
		"Arabic":          arabic.String,
		"Transliteration": transliteration.String,
		"Translation":     translation.String,
		"Notes":           notes.String,
		"Benefits":        benefits.String,
		"Source":          source.String,
	}, nil
}

func GetAdhkarByCategory(category string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`SELECT id, category, title, arabic, translation FROM adhkar WHERE category = ? ORDER BY id`, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var cat, title string
		var arabic, translation sql.NullString
		rows.Scan(&id, &cat, &title, &arabic, &translation)
		results = append(results, map[string]interface{}{
			"ID":          id,
			"Category":    cat,
			"Title":       title,
			"Arabic":      arabic.String,
			"Translation": translation.String,
		})
	}
	return results, nil
}

func GetAdhkarCategories() ([]map[string]interface{}, error) {
	rows, err := DB.Query(`SELECT category, COUNT(*) as count FROM adhkar GROUP BY category ORDER BY category`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var category string
		var count int
		rows.Scan(&category, &count)
		results = append(results, map[string]interface{}{
			"Category": category,
			"Count":    count,
		})
	}
	return results, nil
}

func GetAllAdhkar() ([]map[string]interface{}, error) {
	rows, err := DB.Query(`SELECT id, category, title, arabic, translation FROM adhkar ORDER BY category, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var category, title string
		var arabic, translation sql.NullString
		rows.Scan(&id, &category, &title, &arabic, &translation)
		results = append(results, map[string]interface{}{
			"ID":          id,
			"Category":    category,
			"Title":       title,
			"Arabic":      arabic.String,
			"Translation": translation.String,
		})
	}
	return results, nil
}

func GetAdhkarPrevNext(id int64) (prevID, nextID int64) {
	DB.QueryRow(`SELECT id FROM adhkar WHERE id < ? ORDER BY id DESC LIMIT 1`, id).Scan(&prevID)
	DB.QueryRow(`SELECT id FROM adhkar WHERE id > ? ORDER BY id ASC LIMIT 1`, id).Scan(&nextID)
	return
}

// Riyad us-Saliheen functions

func RiyadCount() int {
	var count int
	DB.QueryRow(`SELECT COUNT(*) FROM salihin`).Scan(&count)
	return count
}

func ClearRiyad() {
	DB.Exec(`DELETE FROM salihin`)
	DB.Exec(`DELETE FROM salihin_fts`)
}

func InsertRiyad(book string, number int, narrator, text, arabic string) error {
	_, err := DB.Exec(`INSERT INTO salihin (book, number, narrator, text, arabic) VALUES (?, ?, ?, ?, ?)`,
		book, number, narrator, text, arabic)
	return err
}

func SearchRiyad(query string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT r.id, r.book, r.number, r.narrator, r.text, r.arabic
		FROM salihin r
		JOIN salihin_fts fts ON r.id = fts.docid
		WHERE salihin_fts MATCH ?
		LIMIT 10
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var number int
		var book, text string
		var narrator, arabic sql.NullString
		rows.Scan(&id, &book, &number, &narrator, &text, &arabic)
		results = append(results, map[string]interface{}{
			"ID":       id,
			"Book":     book,
			"Number":   number,
			"Narrator": narrator.String,
			"Text":     text,
			"Arabic":   arabic.String,
		})
	}
	return results, nil
}

func GetRiyad(id int64) (map[string]interface{}, error) {
	var number int
	var book, text string
	var narrator, arabic sql.NullString
	err := DB.QueryRow(`SELECT id, book, number, narrator, text, arabic FROM salihin WHERE id = ?`, id).Scan(
		&id, &book, &number, &narrator, &text, &arabic)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ID":       id,
		"Book":     book,
		"Number":   number,
		"Narrator": narrator.String,
		"Text":     text,
		"Arabic":   arabic.String,
	}, nil
}

func GetRiyadPrevNext(id int64) (prevID, nextID int64) {
	DB.QueryRow(`SELECT id FROM salihin WHERE id < ? ORDER BY id DESC LIMIT 1`, id).Scan(&prevID)
	DB.QueryRow(`SELECT id FROM salihin WHERE id > ? ORDER BY id ASC LIMIT 1`, id).Scan(&nextID)
	return
}

func GetRiyadBooks() ([]map[string]interface{}, error) {
	rows, err := DB.Query(`SELECT book, COUNT(*) as count FROM salihin GROUP BY book ORDER BY MIN(id)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var book string
		var count int
		rows.Scan(&book, &count)
		results = append(results, map[string]interface{}{
			"Book":  book,
			"Count": count,
		})
	}
	return results, nil
}

func GetRiyadByBook(book string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`SELECT id, number, narrator FROM salihin WHERE book = ? ORDER BY id`, book)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var number int
		var narrator sql.NullString
		rows.Scan(&id, &number, &narrator)
		results = append(results, map[string]interface{}{
			"ID":       id,
			"Number":   number,
			"Narrator": narrator.String,
		})
	}
	return results, nil
}
