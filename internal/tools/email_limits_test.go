package tools

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/client"
)

func TestEmailTextLimit(t *testing.T) {
	for _, n := range []int{maxEmailTextBytes, maxEmailTextBytes + 1} {
		body, auth, err := parseMessage(strings.NewReader("Authentication-Results: mx.google.com; dmarc=pass\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("x", n)))
		if n == maxEmailTextBytes {
			if err != nil || len(body) != n || !strings.Contains(auth, "dmarc=pass") {
				t.Fatalf("valid body: len=%d auth=%q err=%v", len(body), auth, err)
			}
		} else if err == nil || body != "" {
			t.Fatalf("oversize body must be rejected, not truncated: len=%d err=%v", len(body), err)
		}
	}
}

func TestEmailFetchBoundedAndPeek(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	local.SetDeadline(time.Now().Add(5 * time.Second))
	remote.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() {
		fmt.Fprint(remote, "* PREAUTH [CAPABILITY IMAP4rev1] ready\r\n")
		r := bufio.NewReader(remote)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			fields := strings.Fields(line)
			tag := fields[0]
			switch fields[1] {
			case "SELECT":
				fmt.Fprintf(remote, "* 2 EXISTS\r\n%s OK [READ-WRITE] selected\r\n", tag)
			case "UID":
				if fields[2] == "SEARCH" {
					fmt.Fprintf(remote, "* SEARCH 1 2\r\n%s OK searched\r\n", tag)
					continue
				}
				if !strings.Contains(line, fmt.Sprintf("BODY.PEEK[]<0.%d>", maxEmailBytes+1)) || !strings.Contains(line, "RFC822.SIZE") {
					done <- fmt.Errorf("unbounded or non-PEEK fetch: %s", line)
					return
				}
				// Oversized attachment message followed by ordinary mail. The
				// client must drain the fetch and retain the valid second email.
				for i, size := range []int{maxEmailBytes + 100, 80} {
					body := "Content-Type: text/plain\r\n\r\nhello"
					fmt.Fprintf(remote, "* %d FETCH (UID %d RFC822.SIZE %d ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) BODY[]<0> {%d}\r\n%s)\r\n", i+1, i+1, size, len(body), body)
				}
				fmt.Fprintf(remote, "%s OK fetched\r\n", tag)
				done <- nil
				return
			default:
				done <- fmt.Errorf("unexpected command: %s", line)
				return
			}
		}
	}()
	c, err := client.New(local)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Terminate()
	c.Timeout = 5 * time.Second
	s := &Session{c: c}
	emails, err := s.FetchUnread(50)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(emails) != 2 || emails[0].ReadError == "" || emails[0].Body != "" || emails[1].Body != "hello" || emails[1].ReadError != "" {
		t.Fatalf("unexpected fetched emails: %+v", emails)
	}
}

func TestEmailBatchLimit(t *testing.T) {
	for _, n := range []int{-1, 0, 1, 50, 1000000} {
		got := boundedEmailLimit(n)
		if got < 1 || got > maxEmailBatch || (n == 1 && got != 1) {
			t.Fatalf("limit(%d) = %d", n, got)
		}
	}
}
