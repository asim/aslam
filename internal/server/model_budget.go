package server

import (
	"aslam/db"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
)

type modelConversationKey struct{}
type modelQuery struct {
	conversationID int64
	mu             sync.Mutex
	reserved       bool
}

var errModelRestricted = errors.New("AI request blocked")
var modelSlots = make(chan struct{}, 2)

func modelDailyLimit(name string, fallback int) int {
	value := db.GetSetting(name)
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
func reserveModelRequest(ctx context.Context, size int) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if os.Getenv("MODEL_ENABLED") == "false" {
		return nil, fmt.Errorf("%w: AI is disabled", errModelRestricted)
	}
	if size > 64<<10 {
		return nil, fmt.Errorf("%w: conversation or tool results too large; start a shorter chat", errModelRestricted)
	}
	query, _ := ctx.Value(modelConversationKey{}).(*modelQuery)
	if query == nil || query.conversationID <= 0 {
		return nil, fmt.Errorf("%w: conversation required", errModelRestricted)
	}
	select {
	case modelSlots <- struct{}{}:
	default:
		return nil, fmt.Errorf("%w: AI is busy; try again later", errModelRestricted)
	}
	release := func() { <-modelSlots }
	query.mu.Lock()
	defer query.mu.Unlock()
	if !query.reserved {
		if err := db.ReserveModelCall(ctx, query.conversationID, anthropicModel, size, modelDailyLimit("model_daily_question_limit", 0), modelDailyLimit("model_user_daily_question_limit", 5)); err != nil {
			release()
			return nil, err
		}
		query.reserved = true
	}

	return release, nil
}
