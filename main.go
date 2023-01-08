package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/miekg/dns"
)

// The SMTP implements SMTP server methods.
type SMTP struct{}

// A Session is returned after EHLO.
type Session struct {
	// local data
	sync.Mutex
	from, to string
	data     []byte
}

var (
	Domain  = os.Getenv("DOMAIN")
	Address = os.Getenv("ADDRESS")
	Home    = os.Getenv("HOME")
)

var records = map[string]string{
	Domain + ".": Address,
}

func (bkd *SMTP) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &Session{}, nil
}

func (s *Session) AuthPlain(username, password string) error {
	if username != "username" || password != "password" {
		return errors.New("Invalid username or password")
	}
	return nil
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	log.Println("Mail from:", from)
	s.Lock()
	s.from = from
	s.Unlock()
	return nil
}

func (s *Session) Rcpt(to string) error {
	log.Println("Rcpt to:", to)
	s.Lock()
	s.to = to
	s.Unlock()

	return nil
}

func (s *Session) Data(r io.Reader) error {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	} else {
		log.Println("Data:", string(data))
	}

	s.Lock()
	s.data = data
	s.Unlock()

	// save the mail
	s.Save()
	return nil
}

func (s *Session) Save() {
	// timestamp
	t := fmt.Sprintf("%d", time.Now().UnixNano())

	// write a file
	err := os.MkdirAll(Home+"/.aslam/mail", 0755)
	if err != nil && !os.IsExist(err) {
		log.Println(err)
	}

	data := []byte("from: " + s.from + "\n" +
		"to: " + s.to + "\n" +
		"data: " + string(s.data) + "\n\n")

	err = os.WriteFile(Home+"/.aslam/mail/"+t+".txt", data, 0644)
	if err != nil {
		log.Println(err)
	}
}

func (s *Session) Reset() {}

func (s *Session) Logout() error {
	return nil
}

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for A %s\n", q.Name)
			ip := records[q.Name]
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeMX:
			log.Printf("Query for MX %s\n", q.Name)
			ip := records[q.Name]
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s MX 10 %s", q.Name, q.Name))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func dnsServer() {
	dns.HandleFunc(".", handleDnsRequest)
	server := &dns.Server{Addr: ":" + strconv.Itoa(5353), Net: "udp"}
	log.Printf("Starting DNS server at %d\n", 53)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start DNS server: %s\n ", err.Error())
	}
}

func smtpServer() {
	srv := &SMTP{}

	s := smtp.NewServer(srv)

	s.Addr = ":1025"
	s.Domain = Domain
	s.ReadTimeout = 10 * time.Second
	s.WriteTimeout = 10 * time.Second
	s.MaxMessageBytes = 1024 * 1024
	s.MaxRecipients = 50
	s.AllowInsecureAuth = true

	log.Println("Starting SMTP server at", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	if len(Domain) == 0 {
		log.Fatal("require DOMAIN value e.g asl.am.")
	}

	if len(Address) == 0 {
		log.Fatal("require ADDRESS value e.g 1.2.3.4")
	}

	if len(Home) == 0 {
		dirname, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}
		Home = dirname
	}

	go smtpServer()
	dnsServer()
}
