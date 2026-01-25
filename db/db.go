package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

var DB *sql.DB

type Conversation struct {
	ID        int64
	Title     string
	Summary   sql.NullString
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

	return nil
}

// Conversation functions

func GetRecentConversations(limit int) ([]Conversation, error) {
	rows, err := DB.Query(`
		SELECT id, title, summary, created_at, updated_at 
		FROM conversations 
		ORDER BY updated_at DESC 
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var convs []Conversation
	for rows.Next() {
		var c Conversation
		rows.Scan(&c.ID, &c.Title, &c.Summary, &c.CreatedAt, &c.UpdatedAt)
		convs = append(convs, c)
	}
	return convs, nil
}

func GetConversation(id int64) (*Conversation, error) {
	var c Conversation
	err := DB.QueryRow(`
		SELECT id, title, summary, created_at, updated_at 
		FROM conversations WHERE id = ?
	`, id).Scan(&c.ID, &c.Title, &c.Summary, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func CreateConversation(title string) (int64, error) {
	result, err := DB.Exec(`INSERT INTO conversations (title) VALUES (?)`, title)
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

func SearchMessages(query string) ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT m.id, m.conversation_id, m.role, m.content, m.created_at, c.title
		FROM messages m
		JOIN messages_fts fts ON m.id = fts.docid
		JOIN conversations c ON m.conversation_id = c.id
		WHERE messages_fts MATCH ?
		ORDER BY m.created_at DESC
		LIMIT 50
	`, query)
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

// Session functions

func GetSessionByToken(token string) *Session {
	var s Session
	err := DB.QueryRow(`
		SELECT token, email, name, created_at, expires_at 
		FROM sessions WHERE token = ? AND expires_at > CURRENT_TIMESTAMP
	`, token).Scan(&s.Token, &s.Email, &s.Name, &s.CreatedAt, &s.ExpiresAt)
	if err != nil {
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

	expiresAt := time.Now().Add(7 * 24 * time.Hour)
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
