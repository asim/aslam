package tools

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/smtp"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
)

type Email struct {
	UID        uint32
	MessageID  string
	InReplyTo  string
	References string
	From       string
	To         string
	Subject    string
	Date       time.Time
	Body       string
	// AuthResults is the Authentication-Results header added by our own
	// receiving server. See VerifyAuthResults.
	AuthResults string
}

func getEmailConfig() (user, password string, err error) {
	user = os.Getenv("GMAIL_USER")
	password = os.Getenv("GMAIL_APP_PASSWORD")
	if user == "" || password == "" {
		return "", "", fmt.Errorf("GMAIL_USER or GMAIL_APP_PASSWORD not set")
	}
	return user, password, nil
}

// Session is a single authenticated IMAP connection. Reusing one session for a
// whole poll avoids reconnecting and re-authenticating per operation, which
// Gmail rate-limits (it caps simultaneous connections and throttles frequent
// logins).
type Session struct {
	c        *client.Client
	selected bool
}

// Connect opens and authenticates an IMAP session. Call Close when done.
func Connect() (*Session, error) {
	user, password, err := getEmailConfig()
	if err != nil {
		return nil, err
	}
	c, err := client.DialTLS("imap.gmail.com:993", &tls.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	if err := c.Login(user, password); err != nil {
		c.Logout()
		return nil, fmt.Errorf("login failed: %w", err)
	}
	return &Session{c: c}, nil
}

func (s *Session) Close() {
	if s != nil && s.c != nil {
		s.c.Logout()
	}
}

func (s *Session) selectInbox() error {
	if s.selected {
		return nil
	}
	if _, err := s.c.Select("INBOX", false); err != nil {
		return fmt.Errorf("failed to select inbox: %w", err)
	}
	s.selected = true
	return nil
}

// FetchUnread returns unread messages oldest-first, up to limit.
//
// This searches for UNSEEN rather than taking "the last N messages": with a
// fixed window, a burst of mail pushes unprocessed messages out of the window
// and they are silently never handled. Anything not yet dealt with stays
// unread and is picked up on a later cycle instead.
func (s *Session) FetchUnread(limit int) ([]Email, error) {
	if err := s.selectInbox(); err != nil {
		return nil, err
	}

	criteria := imap.NewSearchCriteria()
	criteria.WithoutFlags = []string{imap.SeenFlag}
	uids, err := s.c.UidSearch(criteria)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	if len(uids) == 0 {
		return []Email{}, nil
	}

	// Oldest first so a backlog drains in order rather than starving old mail.
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	if limit > 0 && len(uids) > limit {
		uids = uids[:limit]
	}

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(uids...)
	return s.fetch(seqSet, true)
}

// FetchRecent returns the most recent messages, newest first, regardless of
// read state.
func (s *Session) FetchRecent(limit int) ([]Email, error) {
	// Selected directly rather than via selectInbox: the message count is
	// needed to build the sequence range.
	status, err := s.c.Select("INBOX", false)
	if err != nil {
		return nil, fmt.Errorf("failed to select inbox: %w", err)
	}
	s.selected = true

	if status.Messages == 0 {
		return []Email{}, nil
	}

	from := uint32(1)
	if status.Messages > uint32(limit) {
		from = status.Messages - uint32(limit) + 1
	}
	seqSet := new(imap.SeqSet)
	seqSet.AddRange(from, status.Messages)

	emails, err := s.fetch(seqSet, false)
	if err != nil {
		return nil, err
	}
	// Newest first
	for i, j := 0, len(emails)-1; i < j; i, j = i+1, j-1 {
		emails[i], emails[j] = emails[j], emails[i]
	}
	return emails, nil
}

func (s *Session) fetch(seqSet *imap.SeqSet, byUID bool) ([]Email, error) {
	section := &imap.BodySectionName{}
	items := []imap.FetchItem{imap.FetchEnvelope, imap.FetchFlags, imap.FetchUid, section.FetchItem()}

	messages := make(chan *imap.Message, 32)
	done := make(chan error, 1)
	go func() {
		if byUID {
			done <- s.c.UidFetch(seqSet, items, messages)
		} else {
			done <- s.c.Fetch(seqSet, items, messages)
		}
	}()

	var emails []Email
	for msg := range messages {
		if msg == nil || msg.Envelope == nil {
			continue
		}

		email := Email{
			UID:       msg.Uid,
			MessageID: msg.Envelope.MessageId,
			InReplyTo: msg.Envelope.InReplyTo,
			Subject:   msg.Envelope.Subject,
			Date:      msg.Envelope.Date,
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

		for _, literal := range msg.Body {
			email.Body, email.AuthResults = parseMessage(literal)
		}

		emails = append(emails, email)
	}

	if err := <-done; err != nil {
		return nil, fmt.Errorf("fetch failed: %w", err)
	}
	return emails, nil
}

// MarkRead flags messages as seen in a single round-trip.
func (s *Session) MarkRead(uids ...uint32) error {
	if len(uids) == 0 {
		return nil
	}
	if err := s.selectInbox(); err != nil {
		return err
	}
	seqSet := new(imap.SeqSet)
	seqSet.AddNum(uids...)
	item := imap.FormatFlagsOp(imap.AddFlags, true)
	return s.c.UidStore(seqSet, item, []interface{}{imap.SeenFlag}, nil)
}

// FetchEmails retrieves emails from the inbox on a one-off connection.
func FetchEmails(limit int, unreadOnly bool) ([]Email, error) {
	s, err := Connect()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	if unreadOnly {
		return s.FetchUnread(limit)
	}
	return s.FetchRecent(limit)
}

// parseMessage extracts the text body and the Authentication-Results header.
func parseMessage(r imap.Literal) (body, authResults string) {
	mr, err := mail.CreateReader(r)
	if err != nil {
		// Try reading as plain text
		b, _ := io.ReadAll(r)
		return string(b), ""
	}

	// Headers are prepended by each hop, so the first Authentication-Results
	// is the one our own receiving server added. It is the only one that can
	// be trusted: any others further down may have been forged by the sender.
	authResults = mr.Header.Get("Authentication-Results")

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

	return strings.TrimSpace(body), authResults
}



// SendEmail sends an email via Gmail SMTP
func SendEmail(to, subject, body string) (string, error) {
	return SendEmailThreaded(to, subject, body, "", "")
}

// SendEmailThreaded sends an email with threading headers
// SendEmailThreaded sends an email and returns the Message-ID
func SendEmailThreaded(to, subject, body, inReplyTo, references string) (string, error) {
	user, password, err := getEmailConfig()
	if err != nil {
		return "", err
	}

	// Generate Message-ID
	msgID := fmt.Sprintf("<%d.%s@aslam.org>", time.Now().UnixNano(), randomString(8))

	// Build headers
	var headers strings.Builder
	headers.WriteString(fmt.Sprintf("From: Aslam <%s>\r\n", user))
	headers.WriteString(fmt.Sprintf("To: %s\r\n", to))
	headers.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	headers.WriteString(fmt.Sprintf("Message-ID: %s\r\n", msgID))
	
	if inReplyTo != "" {
		headers.WriteString(fmt.Sprintf("In-Reply-To: %s\r\n", inReplyTo))
	}
	if references != "" {
		headers.WriteString(fmt.Sprintf("References: %s\r\n", references))
	} else if inReplyTo != "" {
		headers.WriteString(fmt.Sprintf("References: %s\r\n", inReplyTo))
	}
	
	headers.WriteString("MIME-Version: 1.0\r\n")
	headers.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	headers.WriteString("\r\n")

	msg := headers.String() + body

	// Connect to Gmail SMTP
	auth := smtp.PlainAuth("", user, password, "smtp.gmail.com")
	err = smtp.SendMail("smtp.gmail.com:587", auth, user, []string{to}, []byte(msg))
	if err != nil {
		return "", fmt.Errorf("failed to send: %w", err)
	}

	return msgID, nil
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(time.Nanosecond)
	}
	return string(b)
}

// MarkAsRead marks an email as read by UID on a one-off connection. Prefer
// Session.MarkRead when several messages are handled in the same poll.
func MarkAsRead(uid uint32) error {
	s, err := Connect()
	if err != nil {
		return err
	}
	defer s.Close()
	return s.MarkRead(uid)
}
