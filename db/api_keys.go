package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type APIKey struct {
	ID                      int64
	Name, Prefix, CreatedAt string
}

func initAPIKeys() error {
	_, err := DB.Exec(`CREATE TABLE IF NOT EXISTS api_keys(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL, prefix TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE INDEX IF NOT EXISTS api_keys_user ON api_keys(user_id)`)
	return err
}
func CreateAPIKey(ctx context.Context, userID int64, name string) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	token := "aslam_" + hex.EncodeToString(random)
	sum := sha256.Sum256([]byte(token))
	result, err := DB.ExecContext(ctx, `INSERT INTO api_keys(user_id,name,prefix,hash) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM users WHERE id=? AND verified=1) AND (SELECT count(*) FROM api_keys WHERE user_id=?)<20`, userID, name, token[:14], hex.EncodeToString(sum[:]), userID, userID)
	if err != nil {
		return "", err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if n != 1 {
		return "", fmt.Errorf("account unavailable or 20-key limit reached")
	}
	return token, nil
}
func APIKeySession(ctx context.Context, token string) (*Session, error) {
	sum := sha256.Sum256([]byte(token))
	var s Session
	err := DB.QueryRowContext(ctx, `SELECT u.email,COALESCE(u.name,'') FROM api_keys k JOIN users u ON u.id=k.user_id WHERE k.hash=? AND u.verified=1`, hex.EncodeToString(sum[:])).Scan(&s.Email, &s.Name)
	return &s, err
}
func ListAPIKeys(ctx context.Context, userID int64) ([]APIKey, error) {
	rows, err := DB.QueryContext(ctx, `SELECT id,name,prefix,created_at FROM api_keys WHERE user_id=? ORDER BY id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
func RevokeAPIKey(ctx context.Context, userID, id int64) error {
	_, err := DB.ExecContext(ctx, "DELETE FROM api_keys WHERE id=? AND user_id=?", id, userID)
	return err
}
