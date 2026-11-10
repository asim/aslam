package db

import (
	"context"
	"fmt"
)

// Evidence is private conversation state, not a chat message or system prompt.
func initToolEvidence() error {
	_, err := DB.Exec(`CREATE TABLE IF NOT EXISTS tool_evidence(id INTEGER PRIMARY KEY,conversation_id INTEGER NOT NULL,tool TEXT NOT NULL,input TEXT NOT NULL,output TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);CREATE INDEX IF NOT EXISTS tool_evidence_conversation ON tool_evidence(conversation_id,id);CREATE TRIGGER IF NOT EXISTS tool_evidence_delete AFTER DELETE ON conversations BEGIN DELETE FROM tool_evidence WHERE conversation_id=old.id; END;`)
	return err
}
func SaveToolEvidence(ctx context.Context, convID int64, tool, input, output string) error {
	if convID <= 0 {
		return fmt.Errorf("conversation required")
	}
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO tool_evidence(conversation_id,tool,input,output) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM conversations WHERE id=?)`, convID, tool, input, output, convID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("conversation no longer exists")
	}
	// Bound retained evidence per conversation. The answer itself keeps citations.
	if _, err = tx.ExecContext(ctx, `DELETE FROM tool_evidence WHERE conversation_id=? AND id NOT IN(SELECT id FROM tool_evidence WHERE conversation_id=? ORDER BY id DESC LIMIT 40)`, convID, convID); err != nil {
		return err
	}
	return tx.Commit()
}
func ToolEvidence(ctx context.Context, convID int64) ([]map[string]interface{}, error) {
	return QueryAPI(ctx, `SELECT tool,input,output FROM tool_evidence WHERE conversation_id=? ORDER BY id DESC LIMIT 12`, convID)
}
