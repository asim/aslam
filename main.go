package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/armon/go-socks5"
	"github.com/emersion/go-smtp"
	"github.com/miekg/dns"
)

// The internal config
type Config struct {
	Domain  string `json:"domain"`
	Address string `json:"address"`
	DNSServers []string `json:"dns_servers"`
}

// DNS server handler
type DNS struct {
	servers []string
}

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

// The SOCKS proxy server
type SOCKS struct {
	config *socks5.Config
}

var (
	Domain  = os.Getenv("DOMAIN")
	Address = os.Getenv("ADDRESS")
	Home    = os.Getenv("HOME")

	// outbound DNS servers
	DNSServers = os.Getenv("DNS_SERVERS")
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
				continue
			}
			if len(d.servers) > 0 {
				log.Printf("External A query to %s for %s", d.servers[0], q.Name)
				mr := new(dns.Msg)
				mr.SetQuestion(q.Name, dns.TypeA)

				if r, err := dns.Exchange(mr, d.servers[0]); err == nil {
					log.Printf("Got response %v", r.Answer)
					m.Answer = append(m.Answer, r.Answer...)
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
				continue
			}

			if len(d.servers) > 0 {
				log.Printf("External MX query to %s for %s", d.servers[0], q.Name)
				mr := new(dns.Msg)
				mr.SetQuestion(q.Name, dns.TypeMX)

				if r, err := dns.Exchange(mr, d.servers[0]); err == nil {
					log.Printf("Got response %v", r.Answer)
					m.Answer = append(m.Answer, r.Answer...)
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
	var servers []string
	if len(DNSServers) > 0 {
		servers = strings.Split(DNSServers, ",")
	}

	server := &dns.Server{
		Addr: ":" + strconv.Itoa(5353),
		Net:  "udp",
		Handler: &DNS{
			servers: servers,
		},
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

func socksServer() {
	conf := &socks5.Config{}

	server, err := socks5.New(conf)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Starting SOCKS server at", 1080)
	if err := server.ListenAndServe("tcp", ":1080"); err != nil {
		log.Fatal(err)
	}
}

func loadConfig() {
	if len(Home) == 0 {
		dirname, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}
		Home = dirname
	}

	configPath := filepath.Join(Home, ".aslam", "config.json")

	// read the config file
	b, err := os.ReadFile(configPath)
	if err == nil {
		c := new(Config)
		if json.Unmarshal(b, &c); err != nil {
			log.Fatal(err)
		}

		log.Println("Loading config", configPath)
		if len(Domain) == 0 {
			Domain = c.Domain
		}
		if len(Address) == 0 {
			Address = c.Address
		}
		if len(DNSServers) == 0 && len(c.DNSServers) > 0 {
			DNSServers = strings.Join(c.DNSServers, ",")
		}
	}

	// load config
	if len(Domain) == 0 {
		log.Fatal("require DOMAIN value e.g asl.am.")
	}

	if len(Address) == 0 {
		log.Fatal("require ADDRESS value e.g 1.2.3.4")
	}

	log.Println("Domain:", Domain)
	log.Println("Address:", Address)
	log.Println("Home:", Home)
	log.Println("DNS Servers:", DNSServers)
}

func main() {
	loadConfig()

	go dnsServer()
	go httpServer()
	go smtpServer()
	go socksServer()

	// catch kill signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGKILL)
	s := <-sigChan

	log.Printf("Received %v, exiting", s)
}
