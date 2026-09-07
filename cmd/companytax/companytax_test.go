package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureProfit(value string) Reports {
	var r Reports
	_ = json.Unmarshal([]byte(`{"Reports":[{"Rows":[{"RowType":"Section","Rows":[{"RowType":"SummaryRow","Cells":[{"Value":"Net Profit"},{"Value":"`+value+`"}]}]}]}]}`), &r)
	return r
}
func reviewed() Config {
	n := 0
	return Config{CompanyName: "MICRO XYZ LTD", CompanyNumber: "16607360", TenantID: "tenant", From: "2025-07-25", To: "2026-07-31", TradingStart: "2025-07-25", Ordinary: true, Associated: &n, Reviews: []Review{{From: "2025-07-25", To: "2026-07-24", Confirmed: true, ProfitLabel: "Net Profit"}}}
}
func TestComputation(t *testing.T) {
	for _, tc := range []struct{ profit, tax string }{{"0", "0.00"}, {"50000", "9500.00"}, {"100000", "22750.00"}, {"250000", "62500.00"}} {
		c := reviewed()
		got := compute(c, Period{c.Reviews[0].From, c.Reviews[0].To}, fixtureProfit(tc.profit))
		if got.Tax != tc.tax {
			t.Fatalf("%s: %+v", tc.profit, got)
		}
	}
	c := reviewed()
	c.Reviews[0].Adjustments = []Adjustment{{Reason: "Depreciation", Amount: "1000.00"}, {Reason: "Capital allowances", Amount: "-500.00"}}
	p := Period{c.Reviews[0].From, c.Reviews[0].To}
	got := compute(c, p, fixtureProfit("10000"))
	if got.Adjusted != "10500.00" || got.Tax != "1995.00" {
		t.Fatal(got)
	}
	c = reviewed()
	n := 1
	c.Associated = &n
	got = compute(c, p, fixtureProfit("50000"))
	if got.Tax != "11375.00" {
		t.Fatal(got)
	}
	c.Reviews[0].From = "2026-07-25"
	c.Reviews[0].To = "2026-07-31"
	got = compute(c, Period{"2026-07-25", "2026-07-31"}, fixtureProfit("10000"))
	if got.Tax != "2500.00" {
		t.Fatal(got)
	}
}
func TestReviewBlocks(t *testing.T) {
	c := reviewed()
	p := Period{c.Reviews[0].From, c.Reviews[0].To}
	c.Associated = nil
	if compute(c, p, fixtureProfit("100")).Tax != "" {
		t.Fatal("unknown associations calculated")
	}
	c = reviewed()
	if compute(c, p, fixtureProfit("-100")).Tax != "" {
		t.Fatal("loss calculated")
	}
	c.Reviews[0].ProfitLabel = "Missing"
	if compute(c, p, fixtureProfit("100")).Tax != "" {
		t.Fatal("missing row calculated")
	}
	c = reviewed()
	c.Ordinary = false
	if compute(c, p, fixtureProfit("100")).Tax != "" {
		t.Fatal("unsupported scope calculated")
	}
	for _, s := range []string{"NaN", "1e3", "1,000", "1.001", ""} {
		if _, err := money(s); err == nil {
			t.Fatal("accepted", s)
		}
	}
}
func TestPeriodsAndConfig(t *testing.T) {
	c := reviewed()
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	s, _ := date(c.TradingStart)
	e, _ := date(c.To)
	p := periods(s, e)
	if len(p) != 2 || p[0].To != "2026-07-24" || p[1].From != "2026-07-25" {
		t.Fatal(p)
	}
	c.TradingStart = ""
	if c.validate() == nil {
		t.Fatal("missing trading date allowed")
	}
	c = reviewed()
	c.Reviews = append(c.Reviews, c.Reviews[0])
	if c.validate() == nil {
		t.Fatal("duplicate reviews allowed")
	}
	if decodeStrict([]byte(`{"typo":true}`), &Config{}) == nil {
		t.Fatal("unknown key allowed")
	}
}
func TestRefreshAndPrepare(t *testing.T) {
	t.Setenv("XERO_CLIENT_ID", "id")
	t.Setenv("XERO_CLIENT_SECRET", "secret")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			id, secret, ok := r.BasicAuth()
			if !ok || id != "id" || secret != "secret" {
				t.Error("bad basic auth")
			}
			r.ParseForm()
			if r.Form.Get("refresh_token") != "old" {
				t.Error("bad refresh")
			}
			w.Write([]byte(`{"access_token":"new","refresh_token":"rotated","expires_in":1800}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer new" {
			t.Error("bad bearer")
		}
		if r.URL.Path == "/connections" {
			w.Write([]byte(`[{"tenantId":"tenant","tenantName":"MICRO XYZ LTD"}]`))
			return
		}
		if r.Header.Get("xero-tenant-id") != "tenant" {
			t.Error("wrong tenant")
		}
		switch r.URL.Path {
		case "/api.xro/2.0/Organisation":
			w.Write([]byte(`{"Organisations":[{"Name":"MICRO XYZ LTD","RegistrationNumber":"16607360","BaseCurrency":"GBP","CountryCode":"GB"}]}`))
		case "/api.xro/2.0/Accounts":
			w.Write([]byte(`{"Accounts":[]}`))
		default:
			calls++
			if r.URL.Query().Get("paymentsOnly") != "false" {
				t.Error("not accrual")
			}
			if strings.HasSuffix(r.URL.Path, "ProfitAndLoss") && r.URL.Query().Get("fromDate") == "" {
				t.Error("no report start")
			}
			json.NewEncoder(w).Encode(fixtureProfit("10000"))
		}
	}))
	defer server.Close()
	state := t.TempDir()
	x := newXero(state)
	x.api = server.URL
	x.identity = server.URL + "/token"
	x.token.Refresh = "old"
	out := filepath.Join(t.TempDir(), "output")
	if err := prepare(context.Background(), x, reviewed(), out); err != nil {
		t.Fatal(err)
	}
	if calls != 5 {
		t.Fatalf("expected five reports, got %d", calls)
	}
	b, err := os.ReadFile(filepath.Join(state, "token.json"))
	if err != nil || !strings.Contains(string(b), "rotated") {
		t.Fatal("rotated token not saved", err)
	}
	st, _ := os.Stat(filepath.Join(state, "token.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("token permissions")
	}
	html, err := os.ReadFile(filepath.Join(out, "report.html"))
	if err != nil || !strings.Contains(string(html), "1900.00") {
		t.Fatal("missing report", err)
	}
	if err := prepare(context.Background(), x, reviewed(), out); err == nil {
		t.Fatal("overwrote output")
	}
}
func TestAPIErrorIsRedacted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429); w.Write([]byte("private body")) }))
	defer server.Close()
	x := newXero(t.TempDir())
	x.api = server.URL
	x.token = token{Access: "ok", Expiry: time.Now().Add(time.Hour)}
	var dst any
	err := x.get(context.Background(), "/Reports", "tenant", url.Values{}, &dst)
	if err == nil || strings.Contains(err.Error(), "private body") {
		t.Fatal(err)
	}
}

func TestPrepareRejectsWrongCompanyAndPartialDownload(t *testing.T) {
	for _, wrongCompany := range []bool{true, false} {
		t.Run(map[bool]string{true: "wrong company", false: "failed report"}[wrongCompany], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/connections":
					w.Write([]byte(`[{"tenantId":"tenant"}]`))
				case "/api.xro/2.0/Organisation":
					number := "16607360"
					if wrongCompany {
						number = "WRONG"
					}
					json.NewEncoder(w).Encode(map[string]any{"Organisations": []map[string]string{{"Name": "MICRO XYZ LTD", "RegistrationNumber": number, "BaseCurrency": "GBP", "CountryCode": "GB"}}})
				case "/api.xro/2.0/Accounts":
					w.Write([]byte(`{"Accounts":[]}`))
				default:
					w.WriteHeader(503)
				}
			}))
			defer server.Close()
			x := newXero(t.TempDir())
			x.api = server.URL
			x.token = token{Access: "ok", Expiry: time.Now().Add(time.Hour)}
			parent := t.TempDir()
			out := filepath.Join(parent, "pack")
			if err := prepare(context.Background(), x, reviewed(), out); err == nil {
				t.Fatal("expected failure")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatal("partial pack left behind", err)
			}
		})
	}
}
