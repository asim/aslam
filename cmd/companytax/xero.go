package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const redirectURI = "http://localhost:5000/callback"
const scopes = "offline_access accounting.settings.read accounting.reports.balancesheet.read accounting.reports.profitandloss.read accounting.reports.trialbalance.read"

type token struct {
	Access    string    `json:"access_token"`
	Refresh   string    `json:"refresh_token"`
	ExpiresIn int       `json:"expires_in"`
	Expiry    time.Time `json:"expiry"`
}
type connection struct {
	ID   string `json:"tenantId"`
	Name string `json:"tenantName"`
}
type xero struct {
	http                 *http.Client
	state, api, identity string
	token                token
}

func newXero(state string) *xero {
	return &xero{http: &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, state: state, api: "https://api.xero.com", identity: "https://identity.xero.com/connect/token"}
}
func (x *xero) load() error {
	b, err := os.ReadFile(filepath.Join(x.state, "token.json"))
	if err != nil {
		return errors.New("no readable Xero token; run companytax login")
	}
	return json.Unmarshal(b, &x.token)
}
func (x *xero) exchange(ctx context.Context, form url.Values) error {
	id, secret := os.Getenv("XERO_CLIENT_ID"), os.Getenv("XERO_CLIENT_SECRET")
	if id == "" || secret == "" {
		return errors.New("set XERO_CLIENT_ID and XERO_CLIENT_SECRET locally")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", x.identity, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := x.http.Do(req)
	if err != nil {
		return errors.New("Xero token request failed; check connectivity and retry")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Xero token request returned HTTP %d; check credentials or run login again", resp.StatusCode)
	}
	var t token
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t); err != nil {
		return errors.New("invalid Xero token response")
	}
	if t.Access == "" || t.Refresh == "" || t.ExpiresIn <= 0 {
		return errors.New("Xero returned an incomplete token; check offline_access permission")
	}
	t.Expiry = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(x.state, ".token-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(x.state, "token.json")); err != nil {
		return err
	}
	x.token = t
	return nil
}
func (x *xero) login(ctx context.Context) error {
	if os.Getenv("XERO_CLIENT_ID") == "" || os.Getenv("XERO_CLIENT_SECRET") == "" {
		return errors.New("set XERO_CLIENT_ID and XERO_CLIENT_SECRET locally")
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	state := hex.EncodeToString(random[:])
	listener, err := net.Listen("tcp4", "127.0.0.1:5000")
	if err != nil {
		return fmt.Errorf("cannot listen on localhost:5000: %w", err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != "GET" || subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(state)) != 1 {
			http.Error(w, "Invalid callback", 400)
			return
		}
		once.Do(func() {
			var err error
			if r.URL.Query().Get("error") != "" || r.URL.Query().Get("code") == "" {
				err = errors.New("Xero authorisation was declined or returned no code")
			} else {
				err = x.exchange(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {r.URL.Query().Get("code")}, "redirect_uri": {redirectURI}})
			}
			if err != nil {
				http.Error(w, "Connection failed. See the terminal.", 400)
			} else {
				fmt.Fprintln(w, "Xero connected. You can close this tab.")
			}
			result <- err
		})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	defer srv.Close()
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case result <- err:
			default:
			}
		}
	}()
	auth := "https://login.xero.com/identity/connect/authorize?" + url.Values{"response_type": {"code"}, "client_id": {os.Getenv("XERO_CLIENT_ID")}, "redirect_uri": {redirectURI}, "scope": {scopes}, "state": {state}}.Encode()
	fmt.Println("Open this URL in a browser on this computer and authorise your company:\n" + auth)
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return errors.New("login timed out; run login again")
	}
}
func (x *xero) get(ctx context.Context, path, tenant string, q url.Values, dst any) error {
	for attempt := 0; attempt < 2; attempt++ {
		if x.token.Access == "" || time.Until(x.token.Expiry) < time.Minute {
			if x.token.Refresh == "" {
				return errors.New("run companytax login")
			}
			if err := x.exchange(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {x.token.Refresh}}); err != nil {
				return err
			}
		}
		req, err := http.NewRequestWithContext(ctx, "GET", x.api+path+"?"+q.Encode(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+x.token.Access)
		req.Header.Set("Accept", "application/json")
		if tenant != "" {
			req.Header.Set("xero-tenant-id", tenant)
		}
		resp, err := x.http.Do(req)
		if err != nil {
			return fmt.Errorf("Xero GET %s failed: %w", path, err)
		}
		if resp.StatusCode == 401 && attempt == 0 {
			resp.Body.Close()
			x.token.Expiry = time.Time{}
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return fmt.Errorf("Xero GET %s: HTTP %d (check access/scopes; for 429 wait and retry)", path, resp.StatusCode)
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(dst)
		resp.Body.Close()
		return err
	}
	return errors.New("Xero access rejected; run login and check app scopes")
}
func (x *xero) connections(ctx context.Context) ([]connection, error) {
	var c []connection
	err := x.get(ctx, "/connections", "", nil, &c)
	return c, err
}
