package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
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

// Emit text before failing so this covers cancellation after response headers,
// unlike TestModelRequestsHonorCancellation's failure before any response.
type streamReadFailure struct{ err error }

func (r streamReadFailure) Read([]byte) (int, error) { return 0, r.err }

func TestModelStreamInterruptedAfterText(t *testing.T) {
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	prefix := "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"partial answer\"}}\n\n"
	for _, tc := range []struct {
		name    string
		readErr error
		cancel  bool
	}{
		{"body read failure", io.ErrUnexpectedEOF, false},
		{"canceled body read", context.Canceled, true},
		{"cancellation at EOF", io.EOF, true},
		{"successful stream", io.EOF, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			http.DefaultTransport = cancelTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(io.MultiReader(strings.NewReader(prefix), streamReadFailure{tc.readErr}))}, nil
			})
			var delivered string
			result, text, err := callAnthropicStream(ctx, nil, "test", func(s string) {
				delivered += s
				if tc.cancel {
					cancel()
				}
			})
			if delivered != "partial answer" || text != delivered {
				t.Fatalf("expected text before interruption: %q / %q", delivered, text)
			}
			wantErr := tc.readErr
			if tc.cancel {
				wantErr = context.Canceled
			}
			if !tc.cancel && tc.readErr == io.EOF {
				if err != nil || result == nil {
					t.Fatalf("successful stream: %v", err)
				}
			} else if !errors.Is(err, wantErr) || result != nil {
				t.Fatalf("interrupted stream accepted: result=%v err=%v", result, err)
			}
		})
	}
}
