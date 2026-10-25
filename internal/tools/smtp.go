package tools

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

type smtpConfig struct{ host, port, from, username, password string }

func outboundSMTPConfig() (smtpConfig, error) {
	c := smtpConfig{host: strings.TrimSpace(os.Getenv("SMTP_HOST")), port: os.Getenv("SMTP_PORT"), from: strings.TrimSpace(os.Getenv("SMTP_FROM")), username: os.Getenv("SMTP_USERNAME"), password: os.Getenv("SMTP_PASSWORD")}
	explicit := c.host != "" || c.port != "" || c.from != "" || c.username != "" || c.password != ""
	if !explicit {
		c.host, c.port = "smtp.gmail.com", "587"
		c.from, c.password = os.Getenv("GMAIL_USER"), os.Getenv("GMAIL_APP_PASSWORD")
		c.username = c.from
		if c.username == "" || c.password == "" {
			return c, fmt.Errorf("outbound SMTP is not configured")
		}
	}
	if c.port == "" {
		c.port = "587"
	}
	port, err := strconv.Atoi(c.port)
	if err != nil || port < 1 || port > 65535 {
		return c, fmt.Errorf("invalid SMTP_PORT")
	}
	if c.host == "" || strings.ContainsAny(c.host, "\r\n /:") {
		return c, fmt.Errorf("SMTP_HOST must be a hostname")
	}
	address, err := mail.ParseAddress(c.from)
	if err != nil || address.Address != c.from || strings.ContainsAny(c.from, "\r\n") {
		return c, fmt.Errorf("SMTP_FROM must be a plain email address")
	}
	if (c.username == "") != (c.password == "") {
		return c, fmt.Errorf("SMTP_USERNAME and SMTP_PASSWORD must both be set or both omitted")
	}
	return c, nil
}

// OutboundEmailConfigured checks sending independently of the assistant inbox.
func OutboundEmailConfigured() bool { _, err := outboundSMTPConfig(); return err == nil }

// sendSMTP requires TLS, bounds the whole exchange, and permits IP-authorized
// relays when no SMTP credentials are configured.
func sendSMTP(c smtpConfig, to string, message []byte) error {
	deadline := time.Now().Add(30 * time.Second)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.host, c.port), 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	tlsConfig := &tls.Config{ServerName: c.host, MinVersion: tls.VersionTLS12}
	if c.port == "465" {
		conn = tls.Client(conn, tlsConfig)
	}
	client, err := smtp.NewClient(conn, c.host)
	if err != nil {
		return err
	}
	defer client.Close()
	// Google relay expects a domain identity rather than Go's default localhost.
	domain := c.from[strings.LastIndex(c.from, "@")+1:]
	if err := client.Hello(domain); err != nil {
		return fmt.Errorf("SMTP greeting failed: %w", err)
	}
	if c.port != "465" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server does not support required STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if c.username != "" {
		if err := client.Auth(smtp.PlainAuth("", c.username, c.password, c.host)); err != nil {
			return err
		}
	}
	if err := client.Mail(c.from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	// DATA acceptance determines success; a QUIT failure must not trigger resend.
	_ = client.Quit()
	return nil
}
