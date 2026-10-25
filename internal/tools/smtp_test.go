package tools

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestOutboundSMTPConfig(t *testing.T) {
	for _, key := range []string{"SMTP_HOST", "SMTP_PORT", "SMTP_FROM", "SMTP_USERNAME", "SMTP_PASSWORD", "GMAIL_USER", "GMAIL_APP_PASSWORD"} {
		t.Setenv(key, "")
	}
	if OutboundEmailConfigured() {
		t.Fatal("missing sender accepted")
	}
	t.Setenv("GMAIL_USER", "old@example.com")
	t.Setenv("GMAIL_APP_PASSWORD", "legacy")
	c, err := outboundSMTPConfig()
	if err != nil || c.host != "smtp.gmail.com" {
		t.Fatal(c, err)
	}
	t.Setenv("SMTP_HOST", "smtp-relay.gmail.com")
	if OutboundEmailConfigured() {
		t.Fatal("partial config fell back to Gmail")
	}
	t.Setenv("SMTP_FROM", "noreply@aslam.org")
	c, err = outboundSMTPConfig()
	if err != nil || c.username != "" || c.password != "" || c.port != "587" {
		t.Fatal("IP relay config", err)
	}
	t.Setenv("SMTP_USERNAME", "sender")
	if OutboundEmailConfigured() {
		t.Fatal("partial credentials accepted")
	}
	t.Setenv("SMTP_PASSWORD", "secret")
	if !OutboundEmailConfigured() {
		t.Fatal("authenticated relay rejected")
	}
	t.Setenv("SMTP_FROM", "noreply@aslam.org\r\nBcc: other@example.com")
	if OutboundEmailConfigured() {
		t.Fatal("header injection accepted")
	}
}

func TestSMTPRefusesPlaintextRelay(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "220 test ESMTP\r\n")
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			done <- err
			return
		}
		if line != "EHLO example.com\r\n" {
			done <- fmt.Errorf("unexpected greeting %q", line)
			return
		}
		fmt.Fprint(conn, "250 test\r\n")
		line, _ = reader.ReadString('\n')
		if strings.HasPrefix(line, "MAIL") || strings.HasPrefix(line, "AUTH") {
			done <- fmt.Errorf("sent on plaintext connection")
			return
		}
		done <- nil
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	err = sendSMTP(smtpConfig{host: host, port: port, from: "noreply@example.com"}, "reader@example.com", []byte("body"))
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSMTPReportsGreetingFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "220 test ESMTP\r\n")
		reader := bufio.NewReader(conn)
		reader.ReadString('\n')
		fmt.Fprint(conn, "421 greeting rejected\r\n")
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	err = sendSMTP(smtpConfig{host: host, port: port, from: "noreply@example.com"}, "reader@example.com", nil)
	if err == nil || !strings.Contains(err.Error(), "SMTP greeting failed") {
		t.Fatalf("lost greeting error: %v", err)
	}
	<-done
}
