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

	// Admins - users who can administer the system
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS admins (
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

	// Vault - things to keep track of (assets, accounts, people, instructions, documents)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS vault (
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
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_vault_category ON vault(category)`)
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_vault_status ON vault(status)`)

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
	log.Printf("DB lookup for token: %q (len=%d)", token, len(token))
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

// Admin functions

type Admin struct {
	ID        int64
	Email     string
	Name      string
	Role      string
	AddedBy   string
	CreatedAt time.Time
}

func GetAdmins() ([]Admin, error) {
	rows, err := DB.Query(`SELECT id, email, name, role, added_by, created_at FROM admins ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var admins []Admin
	for rows.Next() {
		var a Admin
		var name, addedBy sql.NullString
		err := rows.Scan(&a.ID, &a.Email, &name, &a.Role, &addedBy, &a.CreatedAt)
		if err != nil {
			continue
		}
		a.Name = name.String
		a.AddedBy = addedBy.String
		admins = append(admins, a)
	}
	return admins, nil
}

func AddAdmin(email, name, role, addedBy string) error {
	_, err := DB.Exec(`INSERT INTO admins (email, name, role, added_by) VALUES (?, ?, ?, ?)`,
		email, name, role, addedBy)
	return err
}

func RemoveAdmin(id int64) error {
	_, err := DB.Exec(`DELETE FROM admins WHERE id = ?`, id)
	return err
}

func IsAdmin(email string) bool {
	var id int64
	err := DB.QueryRow(`SELECT id FROM admins WHERE email = ?`, email).Scan(&id)
	return err == nil
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

// Vault functions

type VaultItem struct {
	ID          int64
	Category    string
	Name        string
	Description string
	Details     string
	Credentials string
	Notes       string
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func GetVaultItems(category string) ([]VaultItem, error) {
	var query string
	var args []interface{}
	if category != "" {
		query = `SELECT id, category, name, description, details, credentials, notes, status, created_at, updated_at
			FROM vault WHERE category = ? ORDER BY name`
		args = []interface{}{category}
	} else {
		query = `SELECT id, category, name, description, details, credentials, notes, status, created_at, updated_at
			FROM vault ORDER BY category, name`
	}
	
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []VaultItem
	for rows.Next() {
		var v VaultItem
		var desc, details, creds, notes sql.NullString
		err := rows.Scan(&v.ID, &v.Category, &v.Name, &desc, &details, &creds, &notes, &v.Status, &v.CreatedAt, &v.UpdatedAt)
		if err != nil {
			continue
		}
		v.Description = desc.String
		v.Details = details.String
		v.Credentials = creds.String
		v.Notes = notes.String
		items = append(items, v)
	}
	return items, nil
}

func GetVaultItem(id int64) (*VaultItem, error) {
	var v VaultItem
	var desc, details, creds, notes sql.NullString
	err := DB.QueryRow(`
		SELECT id, category, name, description, details, credentials, notes, status, created_at, updated_at
		FROM vault WHERE id = ?
	`, id).Scan(&v.ID, &v.Category, &v.Name, &desc, &details, &creds, &notes, &v.Status, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return nil, err
	}
	v.Description = desc.String
	v.Details = details.String
	v.Credentials = creds.String
	v.Notes = notes.String
	return &v, nil
}

func AddVaultItem(category, name, description, details, credentials, notes string) (int64, error) {
	result, err := DB.Exec(`
		INSERT INTO vault (category, name, description, details, credentials, notes)
		VALUES (?, ?, ?, ?, ?, ?)
	`, category, name, description, details, credentials, notes)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func UpdateVaultItem(id int64, category, name, description, details, credentials, notes, status string) error {
	_, err := DB.Exec(`
		UPDATE vault SET category=?, name=?, description=?, details=?, credentials=?, notes=?, status=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?
	`, category, name, description, details, credentials, notes, status, id)
	return err
}

func DeleteVaultItem(id int64) error {
	_, err := DB.Exec(`DELETE FROM vault WHERE id = ?`, id)
	return err
}

func SearchVault(query string) ([]VaultItem, error) {
	rows, err := DB.Query(`
		SELECT id, category, name, description, details, credentials, notes, status, created_at, updated_at
		FROM vault 
		WHERE name LIKE ? OR description LIKE ? OR details LIKE ? OR notes LIKE ?
		ORDER BY category, name
	`, "%"+query+"%", "%"+query+"%", "%"+query+"%", "%"+query+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []VaultItem
	for rows.Next() {
		var v VaultItem
		var desc, details, creds, notes sql.NullString
		err := rows.Scan(&v.ID, &v.Category, &v.Name, &desc, &details, &creds, &notes, &v.Status, &v.CreatedAt, &v.UpdatedAt)
		if err != nil {
			continue
		}
		v.Description = desc.String
		v.Details = details.String
		v.Credentials = creds.String
		v.Notes = notes.String
		items = append(items, v)
	}
	return items, nil
}

func GetVaultCategories() ([]string, error) {
	rows, err := DB.Query(`SELECT DISTINCT category FROM vault ORDER BY category`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var categories []string
	for rows.Next() {
		var cat string
		rows.Scan(&cat)
		categories = append(categories, cat)
	}
	return categories, nil
}
