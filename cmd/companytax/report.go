package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	CompanyName   string   `json:"company_name"`
	CompanyNumber string   `json:"company_number"`
	TenantID      string   `json:"tenant_id"`
	From          string   `json:"accounts_from"`
	To            string   `json:"accounts_to"`
	TradingStart  string   `json:"trading_start"`
	Ordinary      bool     `json:"ordinary_trading_only_confirmed"`
	Associated    *int     `json:"associated_companies"`
	Reviews       []Review `json:"period_reviews"`
}
type Review struct {
	From        string       `json:"from"`
	To          string       `json:"to"`
	Confirmed   bool         `json:"confirmed"`
	ProfitLabel string       `json:"profit_row_label"`
	Adjustments []Adjustment `json:"adjustments"`
}
type Adjustment struct {
	Reason string `json:"reason"`
	Amount string `json:"amount_gbp"`
}
type Period struct{ From, To string }
type Row struct {
	RowType, Title string
	Cells          []struct{ Value string }
	Rows           []Row
}
type Report struct {
	ReportName   string
	ReportTitles []string
	Rows         []Row
}
type Reports struct{ Reports []Report }
type Sheet struct {
	Name   string
	Titles []string
	Rows   [][]string
}
type Computation struct {
	From, To, Profit, Adjusted, Tax, Rate, Status string
	Adjustments                                   []Adjustment
}
type Pack struct {
	Config       Config
	Generated    string
	Sheets       []Sheet
	Computations []Computation
}

func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}
func date(s string) (time.Time, error) { return time.Parse("2006-01-02", s) }
func (c Config) validate() error {
	if c.CompanyName == "" || c.CompanyNumber == "" || c.TenantID == "" {
		return errors.New("set company_name, company_number and tenant_id (see tenants command)")
	}
	from, e := date(c.From)
	if e != nil {
		return fmt.Errorf("accounts_from: %w", e)
	}
	to, e := date(c.To)
	if e != nil || to.Before(from) {
		return errors.New("invalid accounts_to")
	}
	start, e := date(c.TradingStart)
	if e != nil || start.Before(from) || start.After(to) {
		return errors.New("set the actual trading_start within the accounts period; dormant companies are not supported")
	}
	if to.After(from.AddDate(1, 6, 0).AddDate(0, 0, -1)) {
		return errors.New("accounts period exceeds 18 months")
	}
	if c.Associated != nil && (*c.Associated < 0 || *c.Associated > 10000) {
		return errors.New("associated_companies must be between 0 and 10000, excluding this company")
	}
	valid := map[Period]bool{}
	for _, p := range periods(start, to) {
		valid[p] = true
	}
	seen := map[Period]bool{}
	for _, r := range c.Reviews {
		p := Period{r.From, r.To}
		if !valid[p] || seen[p] {
			return errors.New("period_reviews contains an unmatched or duplicate period")
		}
		seen[p] = true
		for _, a := range r.Adjustments {
			if strings.TrimSpace(a.Reason) == "" {
				return errors.New("every adjustment needs a reason")
			}
			if _, err := money(a.Amount); err != nil {
				return err
			}
		}
	}
	return nil
}
func periods(start, end time.Time) []Period {
	var result []Period
	for !start.After(end) {
		last := start.AddDate(1, 0, 0).AddDate(0, 0, -1)
		if last.After(end) {
			last = end
		}
		result = append(result, Period{start.Format("2006-01-02"), last.Format("2006-01-02")})
		start = last.AddDate(0, 0, 1)
	}
	return result
}

var amountRE = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]{1,2})?$`)

func money(s string) (*big.Rat, error) {
	if !amountRE.MatchString(s) || len(s) > 18 {
		return nil, fmt.Errorf("invalid GBP amount %q; use plain decimal pounds with up to two decimal places", s)
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, errors.New("invalid amount")
	}
	return r, nil
}
func flatten(rows []Row, out *[][]string) {
	for _, r := range rows {
		if r.Title != "" {
			*out = append(*out, []string{r.Title})
		}
		if len(r.Cells) > 0 {
			var cells []string
			for _, c := range r.Cells {
				cells = append(cells, c.Value)
			}
			*out = append(*out, cells)
		}
		flatten(r.Rows, out)
	}
}
func profit(rows []Row, label string) (*big.Rat, error) {
	var found []string
	var visit func([]Row)
	visit = func(rs []Row) {
		for _, r := range rs {
			if len(r.Cells) > 1 && r.Cells[0].Value == label {
				found = append(found, r.Cells[1].Value)
			}
			visit(r.Rows)
		}
	}
	visit(rows)
	if label == "" || len(found) != 1 {
		return nil, fmt.Errorf("profit row %q must match exactly once (found %d); review downloaded P&L", label, len(found))
	}
	return money(found[0])
}

// This intentionally narrow calculation requires an explicit declaration of
// ordinary UK trading profits only, with no distributions or other reliefs.
func compute(c Config, p Period, reports Reports) Computation {
	result := Computation{From: p.From, To: p.To, Status: "NEEDS REVIEW: add a confirmed period_reviews entry, confirm ordinary trading scope and associated companies."}
	var review *Review
	for i := range c.Reviews {
		if c.Reviews[i].From == p.From && c.Reviews[i].To == p.To {
			review = &c.Reviews[i]
		}
	}
	if review == nil || !review.Confirmed || !c.Ordinary || c.Associated == nil {
		return result
	}
	if len(reports.Reports) != 1 {
		result.Status = "BLOCKED: expected one profit-and-loss report"
		return result
	}
	value, err := profit(reports.Reports[0].Rows, review.ProfitLabel)
	if err != nil {
		result.Status = "BLOCKED: " + err.Error()
		return result
	}
	result.Profit = value.FloatString(2)
	result.Adjustments = review.Adjustments
	adjusted := new(big.Rat).Set(value)
	for _, a := range review.Adjustments {
		m, err := money(a.Amount)
		if err != nil {
			result.Status = "BLOCKED: " + err.Error()
			return result
		}
		adjusted.Add(adjusted, m)
	}
	result.Adjusted = adjusted.FloatString(2)
	start, _ := date(p.From)
	end, _ := date(p.To)
	// Rates have been checked for these financial years only.
	if start.Before(time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC)) || !end.Before(time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC)) {
		result.Status = "BLOCKED: rate coverage is 1 April 2025 to 31 March 2027"
		return result
	}
	if adjusted.Sign() < 0 {
		result.Status = "BLOCKED: trading loss requires a loss-relief review; no tax figure calculated"
		return result
	}
	days := int64(end.Sub(start).Hours()/24) + 1
	denominator := int64(365) * int64(1+*c.Associated)
	lower := new(big.Rat).SetFrac64(50000*days, denominator)
	upper := new(big.Rat).SetFrac64(250000*days, denominator)
	tax := new(big.Rat)
	if adjusted.Cmp(lower) <= 0 {
		tax.Mul(adjusted, big.NewRat(19, 100))
		result.Rate = "19% small profits rate"
	} else {
		tax.Mul(adjusted, big.NewRat(25, 100))
		result.Rate = "25% main rate"
		if adjusted.Cmp(upper) < 0 {
			relief := new(big.Rat).Sub(upper, adjusted)
			relief.Mul(relief, big.NewRat(3, 200))
			tax.Sub(tax, relief)
			result.Rate = "25% less marginal relief (augmented profits equal taxable profits)"
		}
	}
	result.Tax = tax.FloatString(2)
	result.Status = "DRAFT: reviewed inputs; verify filing-software rounding and financial-year allocation before submission"
	return result
}

func prepare(ctx context.Context, x *xero, c Config, out string) error {
	list, err := x.connections(ctx)
	if err != nil {
		return err
	}
	matched := false
	for _, item := range list {
		if item.ID == c.TenantID {
			matched = true
		}
	}
	if !matched {
		return errors.New("tenant_id is not among your authorised Xero organisations")
	}
	var org struct {
		Organisations []struct{ Name, LegalName, RegistrationNumber, BaseCurrency, CountryCode string }
	}
	if err = x.get(ctx, "/api.xro/2.0/Organisation", c.TenantID, nil, &org); err != nil {
		return err
	}
	if len(org.Organisations) != 1 {
		return errors.New("expected one organisation")
	}
	o := org.Organisations[0]
	if o.BaseCurrency != "GBP" || o.CountryCode != "GB" {
		return errors.New("this tool supports UK organisations with GBP base currency only")
	}
	norm := func(s string) string { return strings.ToUpper(strings.Join(strings.Fields(s), " ")) }
	if norm(o.LegalName) != norm(c.CompanyName) && norm(o.Name) != norm(c.CompanyName) {
		return errors.New("Xero organisation name does not match company_name; check selected tenant")
	}
	if o.RegistrationNumber != "" && strings.TrimSpace(o.RegistrationNumber) != c.CompanyNumber {
		return errors.New("Xero registration number does not match company_number")
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		return errors.New("output directory must not exist; choose a new --out path")
	}
	parent := filepath.Dir(out)
	if err = os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	temp, err := os.MkdirTemp(parent, ".companytax-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	if err = saveJSON(filepath.Join(temp, "company.json"), c); err != nil {
		return err
	}
	if err = saveJSON(filepath.Join(temp, "organisation.json"), org); err != nil {
		return err
	}
	var accounts json.RawMessage
	if err = x.get(ctx, "/api.xro/2.0/Accounts", c.TenantID, nil, &accounts); err != nil {
		return err
	}
	if err = saveJSON(filepath.Join(temp, "accounts.json"), accounts); err != nil {
		return err
	}
	pack := Pack{Config: c, Generated: time.Now().UTC().Format(time.RFC3339)}
	fetch := func(name, label string, q url.Values) (Reports, error) {
		var raw json.RawMessage
		if err := x.get(ctx, "/api.xro/2.0/Reports/"+name, c.TenantID, q, &raw); err != nil {
			return Reports{}, err
		}
		var reports Reports
		if err := json.Unmarshal(raw, &reports); err != nil {
			return reports, err
		}
		if len(reports.Reports) == 0 {
			return reports, errors.New("Xero returned no reports for " + name)
		}
		if err := saveJSON(filepath.Join(temp, label+".json"), raw); err != nil {
			return reports, err
		}
		for _, r := range reports.Reports {
			sheet := Sheet{Name: label, Titles: r.ReportTitles}
			flatten(r.Rows, &sheet.Rows)
			pack.Sheets = append(pack.Sheets, sheet)
		}
		return reports, nil
	}
	for _, name := range []string{"TrialBalance", "BalanceSheet"} {
		q := url.Values{"date": {c.To}, "paymentsOnly": {"false"}}
		if name == "BalanceSheet" {
			q.Set("standardLayout", "true")
		}
		if _, err = fetch(name, name, q); err != nil {
			return err
		}
	}
	pnl := func(from, to string) url.Values {
		return url.Values{"fromDate": {from}, "toDate": {to}, "standardLayout": {"true"}, "paymentsOnly": {"false"}, "periods": {"1"}}
	}
	if _, err = fetch("ProfitAndLoss", "Accounts-ProfitAndLoss", pnl(c.From, c.To)); err != nil {
		return err
	}
	start, _ := date(c.TradingStart)
	end, _ := date(c.To)
	var suggested []Review
	for _, p := range periods(start, end) {
		r, err := fetch("ProfitAndLoss", "ProfitAndLoss-"+p.From+"-"+p.To, pnl(p.From, p.To))
		if err != nil {
			return err
		}
		pack.Computations = append(pack.Computations, compute(c, p, r))
		suggested = append(suggested, Review{From: p.From, To: p.To, ProfitLabel: "Net Profit", Adjustments: []Adjustment{}})
	}
	if err = saveJSON(filepath.Join(temp, "period-reviews-template.json"), suggested); err != nil {
		return err
	}
	if err = saveJSON(filepath.Join(temp, "computation.json"), pack.Computations); err != nil {
		return err
	}
	t, err := template.New("report").Parse(reportHTML)
	if err != nil {
		return err
	}
	var html bytes.Buffer
	if err = t.Execute(&html, pack); err != nil {
		return err
	}
	if err = writeNew(filepath.Join(temp, "report.html"), html.Bytes()); err != nil {
		return err
	}
	if err = os.Rename(temp, out); err != nil {
		return err
	}
	fmt.Println("Prepared", filepath.Join(out, "report.html"))
	for _, p := range pack.Computations {
		fmt.Printf("%s to %s: %s\n", p.From, p.To, p.Status)
	}
	return nil
}

const reportHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Company tax preparation</title>
<style>body{font:15px/1.5 system-ui;max-width:1050px;margin:40px auto;padding:0 24px;color:#222}table{border-collapse:collapse;width:100%;margin:16px 0}td,th{padding:7px;border-bottom:1px solid #ddd;text-align:left}h2{margin-top:32px}.notice{border:1px solid #aaa;padding:16px}@media print{body{margin:0}h2{break-after:avoid}tr{break-inside:avoid}}</style>
<h1>{{.Config.CompanyName}}</h1><p>Company {{.Config.CompanyNumber}} · Accounts {{.Config.From}} to {{.Config.To}}</p><p>Generated {{.Generated}} · Xero tenant {{.Config.TenantID}}</p>
<div class="notice"><strong>Draft preparation working paper — not a statutory accounts or iXBRL filing package.</strong> Use the source reports and reviewed computation to complete your filing software. Xero reports do not supply statutory disclosures or all tax adjustments. No return has been submitted.</div>
<h2>Review before filing</h2><ul><li>Confirm trading start and HMRC accounting periods, including any pre-trading income or expenses.</li><li>Reconcile the trial balance, bank balances, director loans, share capital and year-end accruals.</li><li>Review depreciation, Corporation Tax expense, disallowable expenses and capital allowances. Add back booked tax if your selected profit row is after tax.</li><li>Check interest, gains, distributions, losses, donations, R&amp;D, group relief and director-loan tax. The simple calculation below does not support these cases.</li><li>Confirm associated companies throughout the period and eligibility for small-profits/marginal relief.</li><li>Prepare statutory accounts/disclosures and the required iXBRL attachments in your filing software.</li></ul>
{{range .Computations}}<h2>Corporation Tax period {{.From}} to {{.To}}</h2><p><strong>{{.Status}}</strong></p>
{{if .Profit}}<table><tr><th>Computation item</th><th>GBP</th></tr><tr><td>Selected Xero profit row</td><td>{{.Profit}}</td></tr>{{range .Adjustments}}<tr><td>{{.Reason}}</td><td>{{.Amount}}</td></tr>{{end}}<tr><td>Adjusted trading profit</td><td>{{.Adjusted}}</td></tr>{{if .Tax}}<tr><td>Estimated Corporation Tax — {{.Rate}}</td><td>{{.Tax}}</td></tr>{{end}}</table><p>For the supported ordinary-trading case, adjusted positive trading profit supplies the trading-profit and taxable-total-profit inputs in your CT600 software. This is not a completed CT600: review its other fields and declarations.</p>{{end}}{{end}}
{{range .Sheets}}<h2>{{.Name}}</h2>{{range .Titles}}<p>{{.}}</p>{{end}}<table>{{range .Rows}}<tr>{{range .}}<td>{{.}}</td>{{end}}</tr>{{end}}</table>{{end}}
<p>Sources: <a href="https://www.gov.uk/government/publications/rates-and-allowances-corporation-tax/rates-and-allowances-corporation-tax">HMRC Corporation Tax rates</a>; <a href="https://www.gov.uk/first-company-accounts-and-return">first accounts and returns</a>.</p></html>`
