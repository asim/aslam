package main

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ReturnPeriod struct {
	From        string      `json:"from"`
	To          string      `json:"to"`
	Computation Computation `json:"computation"`
	TaxPaid     string      `json:"corporation_tax_paid_gbp"`
	Balance     string      `json:"estimated_balance_gbp"`
}
type ReturnData struct {
	Version       int               `json:"version"`
	Status        string            `json:"status"`
	FilingReady   bool              `json:"filing_ready"`
	SourceSHA256  string            `json:"source_sha256"`
	CompanyName   string            `json:"company_name"`
	CompanyNumber string            `json:"company_number"`
	UTR           string            `json:"utr"`
	Facts         map[string]string `json:"reviewed_answers"`
	Periods       []ReturnPeriod    `json:"periods"`
	Outstanding   []string          `json:"outstanding"`
}

func generateCommand(data, path, out string) error {
	s, e := loadSnapshot(data)
	if e != nil {
		return e
	}
	path = answerPath(data, path)
	unlock, e := fileLock(path + ".lock")
	if e != nil {
		return e
	}
	defer unlock()
	a, e := loadAnswers(path, s.Fingerprint)
	if e != nil {
		return e
	}
	return generateReviewed(s, a, out)
}

func generateReviewed(s Snapshot, a Answers, out string) error {
	if a.Version != 1 || a.Fingerprint != s.Fingerprint {
		return errors.New("review does not match this snapshot")
	}
	ask := func(q question) (string, error) {
		v, ok := a.Values[q.Key]
		if !ok {
			return "", fmt.Errorf("missing answer %s; run review to resume", q.Key)
		}
		if e := q.Check(v); e != nil {
			return "", fmt.Errorf("invalid answer %s: %w", q.Key, e)
		}
		return v, nil
	}
	r, e := walkReview(s, ask, io.Discard)
	if e != nil {
		return e
	}
	if len(r.Blockers) > 0 {
		return fmt.Errorf("generation blocked:\n- %s\nRun review --edit to correct the answers; unsupported tax cases require additional computation", strings.Join(r.Blockers, "\n- "))
	}
	pack := s.Pack
	pack.Config = r.Config
	pack.Computations = nil
	pack.Generated = time.Now().UTC().Format(time.RFC3339)
	ret := ReturnData{Version: 1, Status: "Reviewed draft; statutory accounts and submission-format validation outstanding", SourceSHA256: s.Fingerprint, CompanyName: r.Config.CompanyName, CompanyNumber: r.Config.CompanyNumber, UTR: r.Facts["utr"], Facts: r.Facts,
		Outstanding: []string{"Complete statutory accounts and disclosures, with director approval", "Generate and validate CT600 and any supplementary pages in the required submission format", "Generate and validate iXBRL accounts and computations", "Verify financial-year allocations, claim elections and filing-software rounding"}}
	for i, p := range s.Periods {
		c := compute(r.Config, p, s.Reports[i])
		if c.Tax == "" {
			return fmt.Errorf("generation blocked for %s: %s", p.From, c.Status)
		}
		paid, _ := money(r.Facts[p.From+"/tax_paid"])
		tax, _ := money(c.Tax)
		balance := new(big.Rat).Sub(tax, paid)
		ret.Periods = append(ret.Periods, ReturnPeriod{p.From, p.To, c, paid.FloatString(2), balance.FloatString(2)})
		pack.Computations = append(pack.Computations, c)
	}
	if _, e = os.Stat(out); !os.IsNotExist(e) {
		return errors.New("output directory must not exist; choose a new --out")
	}
	parent := filepath.Dir(out)
	if e = os.MkdirAll(parent, 0700); e != nil {
		return e
	}
	temp, e := os.MkdirTemp(parent, ".companytax-generated-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	if e = saveJSON(filepath.Join(temp, "return-data.json"), ret); e != nil {
		return e
	}
	if e = saveJSON(filepath.Join(temp, "reviewed-config.json"), r.Config); e != nil {
		return e
	}
	if e = saveJSON(filepath.Join(temp, "computation.json"), pack.Computations); e != nil {
		return e
	}
	render := func(name, text string, v any) error {
		t, e := template.New(name).Parse(text)
		if e != nil {
			return e
		}
		var b bytes.Buffer
		if e = t.Execute(&b, v); e != nil {
			return e
		}
		return writeNew(filepath.Join(temp, name), b.Bytes())
	}
	if e = render("report.html", reportHTML, pack); e != nil {
		return e
	}
	if e = render("return-review.html", returnReviewHTML, ret); e != nil {
		return e
	}
	if e = os.Rename(temp, out); e != nil {
		return e
	}
	fmt.Println("Generated", filepath.Join(out, "return-review.html"))
	fmt.Println("This contains the reviewed facts and computations; it is not yet a completed CT600/iXBRL filing package.")
	return nil
}

const returnReviewHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Reviewed company tax information</title>
<style>body{font:15px/1.5 system-ui;max-width:1000px;margin:40px auto;padding:0 24px}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:8px;text-align:left;overflow-wrap:anywhere}.notice{border:1px solid #999;padding:16px}h2{margin-top:32px}@media print{tr{break-inside:avoid}h2{break-after:avoid}}</style>
<h1>{{.CompanyName}}</h1><p>Company number {{.CompanyNumber}} · Corporation Tax UTR {{.UTR}}</p>
<p class="notice"><strong>{{.Status}}.</strong> These are reviewed facts for the return, not a completed CT600 or upload-ready iXBRL. No filing or declaration has been made.</p>
{{range .Periods}}<h2>{{.From}} to {{.To}}</h2><table><tr><th>Item</th><th>GBP</th></tr><tr><td>Profit per selected Xero row</td><td>{{.Computation.Profit}}</td></tr>{{range .Computation.Adjustments}}<tr><td>{{.Reason}}</td><td>{{.Amount}}</td></tr>{{end}}<tr><td>Adjusted ordinary trading profits</td><td>{{.Computation.Adjusted}}</td></tr><tr><td>Estimated Corporation Tax</td><td>{{.Computation.Tax}}</td></tr><tr><td>Tax already paid</td><td>{{.TaxPaid}}</td></tr><tr><td>Estimated balance (negative means potential overpayment)</td><td>{{.Balance}}</td></tr></table><p>{{.Computation.Rate}}</p>{{end}}
<h2>Saved review answers</h2><table>{{range $key,$value := .Facts}}<tr><th>{{$key}}</th><td>{{$value}}</td></tr>{{end}}</table>
<h2>Still required for a complete filing</h2><ul>{{range .Outstanding}}<li>{{.}}</li>{{end}}</ul>
<p>Source snapshot SHA-256: {{.SourceSHA256}}. The accompanying report.html contains the Xero source tables.</p></html>`
