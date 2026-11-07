package db

import (
	"context"
	"errors"
	"fmt"
)

var ErrModelBudget = errors.New("AI daily limit reached; please try again tomorrow (UTC)")

// ReserveModelCall reserves one initial question. Follow-up provider calls share
// the reservation. Failed initial attempts remain counted. A zero global limit is unlimited.
func ReserveModelCall(ctx context.Context, convID int64, model string, size, globalLimit, userLimit int) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	if DB == nil {
		return fmt.Errorf("AI usage database unavailable")
	}
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// BeginTx is deferred in SQLite. Acquire the write reservation before any
	// SELECT so concurrent requests wait under busy_timeout rather than racing
	// to upgrade shared read locks. This updates no rows.
	if _, err := tx.ExecContext(ctx, "UPDATE model_daily_usage SET calls=calls WHERE 0"); err != nil {
		return err
	}
	var userID int64
	if err := tx.QueryRowContext(ctx, `SELECT u.id FROM conversations c JOIN users u ON u.id=c.user_id WHERE c.id=? AND u.verified=1`, convID).Scan(&userID); err != nil {
		return fmt.Errorf("AI requires an active account owning the conversation")
	}
	for _, budget := range []struct {
		id    int64
		limit int
	}{{0, globalLimit}, {userID, userLimit}} {
		result, err := tx.ExecContext(ctx, `INSERT INTO model_daily_usage(day,user_id,calls,request_bytes) SELECT date('now'),?,1,? WHERE (? > 0 OR ? = 0) ON CONFLICT(day,user_id) DO UPDATE SET calls=calls+1,request_bytes=request_bytes+excluded.request_bytes WHERE calls<? OR (? = 0 AND ? = 0)`, budget.id, size, budget.limit, budget.id, budget.limit, budget.id, budget.limit)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrModelBudget
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO model_calls(user_id,conversation_id,model,request_bytes) VALUES(?,?,?,?)`, userID, convID, model, size); err != nil {
		return err
	}
	return tx.Commit()
}

type ModelUsage struct {
	Email        string
	Calls, Bytes int64
}

func GetModelUsage(ctx context.Context) ([]ModelUsage, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := DB.QueryContext(ctx, `SELECT CASE WHEN m.user_id=0 THEN 'All users' ELSE COALESCE(u.email,'Deleted account') END,m.calls,m.request_bytes FROM model_daily_usage m LEFT JOIN users u ON u.id=m.user_id WHERE m.day=date('now') ORDER BY m.user_id=0 DESC,m.calls DESC LIMIT 101`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ModelUsage
	for rows.Next() {
		var v ModelUsage
		if err := rows.Scan(&v.Email, &v.Calls, &v.Bytes); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ModelActivity reports initial question attempts, not reading or browsing activity.
// Audit events are retained for 90 days at startup.
type ModelActivity struct {
	Email      string
	Questions  int64
	LastActive string
}

func GetModelActivity(ctx context.Context) ([]ModelActivity, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := DB.QueryContext(ctx, `SELECT COALESCE(u.email,'Deleted account'),count(*),max(m.created_at)
 FROM model_calls m LEFT JOIN users u ON u.id=m.user_id
 WHERE m.created_at>=datetime('now','-30 days')
 GROUP BY m.user_id ORDER BY max(m.created_at) DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ModelActivity
	for rows.Next() {
		var v ModelActivity
		if err := rows.Scan(&v.Email, &v.Questions, &v.LastActive); err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}
