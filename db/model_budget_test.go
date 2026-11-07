package db

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestModelQuota(t *testing.T) {
	setupTestDB(t)
	_, err := DB.Exec("INSERT INTO users(id,email,verified,role) VALUES(1,'a@example.com',1,'user'),(2,'b@example.com',1,'user'); INSERT INTO conversations(id,title,user_id) VALUES(1,'a',1),(2,'b',2)")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	reserve := func(id int64, g, u int) error { return ReserveModelCall(ctx, id, "test", 10, g, u) }
	if err := reserve(1, 3, 1); err != nil {
		t.Fatal(err)
	}
	if err := reserve(1, 3, 1); !errors.Is(err, ErrModelBudget) {
		t.Fatal(err)
	}
	if err := reserve(2, 3, 2); err != nil {
		t.Fatal(err)
	}
	if err := reserve(2, 3, 2); err != nil {
		t.Fatal(err)
	}
	if err := reserve(2, 3, 5); !errors.Is(err, ErrModelBudget) {
		t.Fatal(err)
	}
	var n int
	DB.QueryRow("SELECT calls FROM model_daily_usage WHERE user_id=0").Scan(&n)
	if n != 3 {
		t.Fatalf("rollback failed: %d", n)
	}
	if err := reserve(999, 100, 100); err == nil {
		t.Fatal("missing owner allowed")
	}
	DB.Exec("DELETE FROM model_daily_usage")
	if err := reserve(1, 100, 0); !errors.Is(err, ErrModelBudget) {
		t.Fatal(err)
	}
	DB.Exec("INSERT INTO model_daily_usage VALUES('2000-01-01',0,999,10)")
	if err := reserve(1, 1, 1); err != nil {
		t.Fatal(err)
	}
}
func TestConcurrentModelQuota(t *testing.T) {
	setupTestDB(t)
	DB.Exec("INSERT INTO users(id,email,verified,role) VALUES(1,'a@example.com',1,'user'); INSERT INTO conversations(id,title,user_id) VALUES(1,'a',1)")
	var wg sync.WaitGroup
	var succeeded atomic.Int32
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ReserveModelCall(context.Background(), 1, "test", 10, 5, 5)
			if err == nil {
				succeeded.Add(1)
			} else if !errors.Is(err, ErrModelBudget) {
				t.Errorf("reservation should succeed or exhaust quota, got %v", err)
			}
		}()
	}
	wg.Wait()
	if succeeded.Load() != 5 {
		t.Fatalf("unexpected successes %d", succeeded.Load())
	}
	var n int
	if err := DB.QueryRow("SELECT calls FROM model_daily_usage WHERE user_id=0").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if int32(n) != succeeded.Load() {
		t.Fatalf("accounting mismatch: %d / %d", n, succeeded.Load())
	}
}

func TestAdminModelQuotaExemption(t *testing.T) {
	setupTestDB(t)
	if _, err := DB.Exec("INSERT INTO users(id,email,verified,role) VALUES(1,'admin@example.com',1,'admin'),(2,'user@example.com',1,'user'); INSERT INTO conversations(id,title,user_id) VALUES(1,'admin',1),(2,'user',2)"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Fill the site-wide allowance, then verify admins ignore it and zero user limits.
	if err := ReserveModelCall(ctx, 2, "test", 10, 1, 1); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if err := ReserveModelCall(ctx, 1, "test", 10, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := DB.QueryRow("SELECT calls FROM model_daily_usage WHERE user_id=0").Scan(&count); err != nil || count != 1 {
		t.Fatalf("admin consumed site quota: %d %v", count, err)
	}
	if err := DB.QueryRow("SELECT calls FROM model_daily_usage WHERE user_id=1").Scan(&count); err != nil || count != 6 {
		t.Fatalf("admin usage missing: %d %v", count, err)
	}
	if err := ReserveModelCall(ctx, 2, "test", 10, 1, 10); !errors.Is(err, ErrModelBudget) {
		t.Fatalf("ordinary account bypass: %v", err)
	}
	if _, err := DB.Exec("UPDATE users SET role='user' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := ReserveModelCall(ctx, 1, "test", 10, 1, 0); !errors.Is(err, ErrModelBudget) {
		t.Fatalf("role change ignored: %v", err)
	}
}
