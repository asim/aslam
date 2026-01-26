package tools

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
)

type Email struct {
	UID     uint32
	From    string
	To      string
	Subject string
	Date    time.Time
	Body    string
}

func getEmailConfig() (user, password string, err error) {
	user = os.Getenv("GMAIL_USER")
	password = os.Getenv("GMAIL_APP_PASSWORD")
	if user == "" || password == "" {
		return "", "", fmt.Errorf("GMAIL_USER or GMAIL_APP_PASSWORD not set")
	}
	return user, password, nil
}

// FetchEmails retrieves recent emails from inbox
func FetchEmails(limit int, unreadOnly bool) ([]Email, error) {
	user, password, err := getEmailConfig()
	if err != nil {
		return nil, err
	}

	// Connect to Gmail IMAP
	c, err := client.DialTLS("imap.gmail.com:993", &tls.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer c.Logout()

	// Login
	if err := c.Login(user, password); err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	// Select INBOX
	mbox, err := c.Select("INBOX", false)
	if err != nil {
		return nil, fmt.Errorf("failed to select inbox: %w", err)
	}

	if mbox.Messages == 0 {
		return []Email{}, nil
	}

	// Build sequence set for last N messages
	from := uint32(1)
	if mbox.Messages > uint32(limit) {
		from = mbox.Messages - uint32(limit) + 1
	}
	seqSet := new(imap.SeqSet)
	seqSet.AddRange(from, mbox.Messages)

	// Fetch messages
	section := &imap.BodySectionName{}
	items := []imap.FetchItem{imap.FetchEnvelope, imap.FetchFlags, imap.FetchUid, section.FetchItem()}

	messages := make(chan *imap.Message, limit)
	done := make(chan error, 1)
	go func() {
		done <- c.Fetch(seqSet, items, messages)
	}()

	var emails []Email
	for msg := range messages {
		if msg == nil || msg.Envelope == nil {
			continue
		}

		// Skip read messages if unreadOnly
		if unreadOnly {
			seen := false
			for _, flag := range msg.Flags {
				if flag == imap.SeenFlag {
					seen = true
					break
				}
			}
			if seen {
				continue
			}
		}

		email := Email{
			UID:     msg.Uid,
			Subject: msg.Envelope.Subject,
			Date:    msg.Envelope.Date,
		}

		if len(msg.Envelope.From) > 0 {
			addr := msg.Envelope.From[0]
			if addr.PersonalName != "" {
				email.From = fmt.Sprintf("%s <%s@%s>", addr.PersonalName, addr.MailboxName, addr.HostName)
			} else {
				email.From = fmt.Sprintf("%s@%s", addr.MailboxName, addr.HostName)
			}
		}

		if len(msg.Envelope.To) > 0 {
			addr := msg.Envelope.To[0]
			email.To = fmt.Sprintf("%s@%s", addr.MailboxName, addr.HostName)
		}

		// Extract body
		for _, literal := range msg.Body {
			email.Body = extractBody(literal)
		}

		emails = append(emails, email)
	}

	if err := <-done; err != nil {
		return nil, fmt.Errorf("fetch failed: %w", err)
	}

	// Reverse to get newest first
	for i, j := 0, len(emails)-1; i < j; i, j = i+1, j-1 {
		emails[i], emails[j] = emails[j], emails[i]
	}

	return emails, nil
}

func extractBody(r imap.Literal) string {
	mr, err := mail.CreateReader(r)
	if err != nil {
		// Try reading as plain text
		body, _ := io.ReadAll(r)
		return string(body)
	}

	var body string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}

		switch h := p.Header.(type) {
		case *mail.InlineHeader:
			contentType, _, _ := h.ContentType()
			if strings.HasPrefix(contentType, "text/plain") {
				b, _ := io.ReadAll(p.Body)
				body = string(b)
			} else if strings.HasPrefix(contentType, "text/html") && body == "" {
				b, _ := io.ReadAll(p.Body)
				body = stripHTML(string(b))
			}
		}
	}

	return strings.TrimSpace(body)
}



// SendEmail sends an email via Gmail SMTP
func SendEmail(to, subject, body string) error {
	user, password, err := getEmailConfig()
	if err != nil {
		return err
	}

	// Build message
	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		"\r\n"+
		"%s", user, to, subject, body)

	// Connect to Gmail SMTP
	auth := smtp.PlainAuth("", user, password, "smtp.gmail.com")
	err = smtp.SendMail("smtp.gmail.com:587", auth, user, []string{to}, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send: %w", err)
	}

	return nil
}

// MarkAsRead marks an email as read by UID
func MarkAsRead(uid uint32) error {
	user, password, err := getEmailConfig()
	if err != nil {
		return err
	}

	c, err := client.DialTLS("imap.gmail.com:993", &tls.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer c.Logout()

	if err := c.Login(user, password); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	if _, err := c.Select("INBOX", false); err != nil {
		return fmt.Errorf("failed to select inbox: %w", err)
	}

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(uid)

	item := imap.FormatFlagsOp(imap.AddFlags, true)
	flags := []interface{}{imap.SeenFlag}
	return c.UidStore(seqSet, item, flags, nil)
}
