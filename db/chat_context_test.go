package db

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestChatLookupsCancelWhilePoolBusy(t *testing.T) {
	limitedTestDB(t)
	conn, err := DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, lookup := range []func(context.Context) error{
		func(ctx context.Context) error { _, err := GetUserByIDContext(ctx, 1); return err },
		func(ctx context.Context) error { _, err := GetConversationContext(ctx, 1); return err },
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		err := lookup(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected deadline, got %v", err)
		}
	}
}
