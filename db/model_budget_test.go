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
	_, err := DB.Exec("INSERT INTO users(id,email,verified) VALUES(1,'a@example.com',1),(2,'b@example.com',1); INSERT INTO conversations(id,title,user_id) VALUES(1,'a',1),(2,'b',2)")
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
	DB.Exec("INSERT INTO users(id,email,verified) VALUES(1,'a@example.com',1); INSERT INTO conversations(id,title,user_id) VALUES(1,'a',1)")
	var wg sync.WaitGroup
	var succeeded atomic.Int32
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ReserveModelCall(context.Background(), 1, "test", 10, 5, 5) == nil {
				succeeded.Add(1)
			}
		}()
	}
	wg.Wait()
	if succeeded.Load() > 5 || succeeded.Load() == 0 {
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
