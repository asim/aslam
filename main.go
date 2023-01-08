package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/miekg/dns"
)

// DNS server handler
type DNS struct{}

// The SMTP implements SMTP server methods.
type SMTP struct{}

// A Session is returned after EHLO.
type Session struct {
	// local data
	sync.Mutex
	from, to string
	data     []byte
}

// The HTTP server handler
type HTTP struct{}

var (
	Domain  = os.Getenv("DOMAIN")
	Address = os.Getenv("ADDRESS")
	Home    = os.Getenv("HOME")
)

// DNS records
var records = map[string]string{
	Domain + ".": Address,
}

func (d *DNS) parseQuery(m *dns.Msg) {
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

func (d *DNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		d.parseQuery(m)
	}

	w.WriteMsg(m)
}

func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// set server header
	w.Header().Set("Server", "aslam")
	// handle request
	http.DefaultServeMux.ServeHTTP(w, r)
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

func dnsServer() {
	server := &dns.Server{
		Addr:    ":" + strconv.Itoa(5353),
		Net:     "udp",
		Handler: &DNS{},
	}
	log.Printf("Starting DNS server at %d\n", 53)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start DNS server: %s\n ", err.Error())
	}
}

func httpServer() {
	srv := &HTTP{}

	// write a file
	err := os.MkdirAll(Home+"/.aslam/web", 0755)
	if err != nil && !os.IsExist(err) {
		log.Println(err)
	} else if err == nil {
		// made a dir, add an index file
		os.WriteFile(Home+"/.aslam/web/index.html", []byte(`<html>
		<body><head><title>Aslam Web Server</title></head>
		<h1>Hello world!</h1></body>
		</html>`), 0644)
	}

	fs := http.FileServer(http.Dir(Home + "/.aslam/web"))
	http.Handle("/", fs)
	log.Printf("Starting HTTP server at %d\n", 8080)
	err = http.ListenAndServe(":8080", srv)
	if err != nil {
		log.Fatalf("Failed to start HTTP server: %s\n", err.Error())
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
	go httpServer()
	go dnsServer()

	// catch kill signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGKILL)
	s := <-sigChan

	log.Printf("Received %v, exiting", s)
}
