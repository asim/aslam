package server

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type cancelTransport func(*http.Request) (*http.Response, error)

func (f cancelTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestModelRequestsHonorCancellation(t *testing.T) {
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	for _, stream := range []bool{false, true} {
		started := make(chan struct{})
		http.DefaultTransport = cancelTransport(func(r *http.Request) (*http.Response, error) {
			close(started)
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			if stream {
				_, _, err := callAnthropicStream(ctx, nil, "test", func(string) {})
				done <- err
			} else {
				_, err := callAnthropic(ctx, nil, "test")
				done <- err
			}
		}()
		select {
		case <-started:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("model request not started")
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected canceled request: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("model request stayed open")
		}
	}
}
