package db

import (
	"context"
	"fmt"
)

type SignupRequest struct {
	Email, Name, Token, Expires string
	Verified                    bool
}

func GetSignupRequests(ctx context.Context) ([]SignupRequest, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := DB.QueryContext(ctx, `SELECT email,COALESCE(name,''),verify_token,expires_at,email_verified FROM pending_signups WHERE expires_at>CURRENT_TIMESTAMP ORDER BY email_verified DESC,verify_sent_at DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SignupRequest
	for rows.Next() {
		var r SignupRequest
		if err := rows.Scan(&r.Email, &r.Name, &r.Token, &r.Expires, &r.Verified); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func ReviewSignup(ctx context.Context, email, token string, approve bool) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if approve {
		result, err := tx.ExecContext(ctx, `INSERT INTO users(email,name,password_hash,role,added_by,verified) SELECT email,name,password_hash,'user','signup',1 FROM pending_signups WHERE email=? AND verify_token=? AND email_verified=1 AND expires_at>CURRENT_TIMESTAMP`, email, token)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("request must be verified and unexpired")
		}
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM pending_signups WHERE email=? AND verify_token=?`, email, token)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("request no longer exists")
	}
	return tx.Commit()
}

// PendingSignupPassword only supports showing approval status after proving the
// password, without creating a session or exposing addresses to anonymous users.
func PendingSignupPassword(ctx context.Context, email string) string {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	var hash string
	DB.QueryRowContext(ctx, `SELECT password_hash FROM pending_signups WHERE email=? AND email_verified=1 AND expires_at>CURRENT_TIMESTAMP`, email).Scan(&hash)
	return hash
}
