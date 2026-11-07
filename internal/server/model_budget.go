package server

import (
	"aslam/db"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
)

type modelConversationKey struct{}

var errModelRestricted = errors.New("AI request blocked")
var modelSlots = make(chan struct{}, 2)

func modelDailyLimit(name string, fallback int) int {
	value := os.Getenv(name)
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
	convID, _ := ctx.Value(modelConversationKey{}).(int64)
	if convID <= 0 {
		return nil, fmt.Errorf("%w: conversation required", errModelRestricted)
	}
	select {
	case modelSlots <- struct{}{}:
	default:
		return nil, fmt.Errorf("%w: AI is busy; try again later", errModelRestricted)
	}
	release := func() { <-modelSlots }
	if err := db.ReserveModelCall(ctx, convID, anthropicModel, size, modelDailyLimit("MODEL_DAILY_CALL_LIMIT", 100), modelDailyLimit("MODEL_USER_DAILY_CALL_LIMIT", 20)); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
