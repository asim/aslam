package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Answers are bound to the exact downloaded evidence, not just its dates.
type Answers struct {
	Version     int               `json:"version"`
	Fingerprint string            `json:"source_sha256"`
	Values      map[string]string `json:"answers"`
}
type Snapshot struct {
	Pack        Pack
	Periods     []Period
	Reports     []Reports
	Fingerprint string
}
type question struct {
	Key, Text, Default string
	Check              func(string) error
}
type askFunc func(question) (string, error)
type terminal struct {
	in  *bufio.Scanner
	out io.Writer
}

func newTerminal(in io.Reader, out io.Writer) *terminal {
	s := bufio.NewScanner(in)
	s.Buffer(make([]byte, 4096), 1024*1024)
	return &terminal{s, out}
}
func (t *terminal) ask(q question) (string, error) {
	for {
		fmt.Fprint(t.out, q.Text)
		if q.Default != "" {
			fmt.Fprintf(t.out, " [%s]", q.Default)
		}
		fmt.Fprint(t.out, ": ")
		if !t.in.Scan() {
			if err := t.in.Err(); err != nil {
				return "", err
			}
			return "", errors.New("review paused; previous answers are saved; rerun the same command to resume")
		}
		v := strings.TrimSpace(t.in.Text())
		if v == "" {
			v = q.Default
		}
		if q.Check != nil {
			if err := q.Check(v); err != nil {
				fmt.Fprintln(t.out, err)
				continue
			}
		}
		return v, nil
	}
}
func required(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("a value is required")
	}
	return nil
}
func yesNo(s string) error {
	if s != "yes" && s != "no" {
		return errors.New("enter yes or no")
	}
	return nil
}
func count(s string) error {
	n, e := strconv.Atoi(s)
	if e != nil || n < 0 || n > 1000 {
		return errors.New("enter a whole number between 0 and 1000")
	}
	return nil
}
func nonnegative(s string) error {
	m, e := money(s)
	if e != nil {
		return e
	}
	if m.Sign() < 0 {
		return errors.New("enter zero or a positive amount")
	}
	return nil
}
func validDate(s string) error { _, e := date(s); return e }

var utrRE = regexp.MustCompile(`^[0-9]{10}$`)

func validUTR(s string) error {
	if !utrRE.MatchString(s) {
		return errors.New("enter the company's 10-digit Corporation Tax UTR, not its VAT number")
	}
	return nil
}

func atomicJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	dir := filepath.Dir(path)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".review-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(append(b, '\n')); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(name, path)
}
func fileLock(path string) (func(), error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, fmt.Errorf("cannot acquire %s; check for another process or a stale lock: %w", path, e)
	}
	f.Close()
	return func() { os.Remove(path) }, nil
}
func answerPath(data, path string) string {
	if path != "" {
		return path
	}
	return filepath.Join(data, "review.json")
}

func loadSnapshot(dir string) (Snapshot, error) {
	var s Snapshot
	hash := sha256.New()
	read := func(name string, v any) error {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			return e
		}
		fmt.Fprintf(hash, "%s\x00%d\x00", name, len(b))
		hash.Write(b)
		return json.Unmarshal(b, v)
	}
	if e := read("company.json", &s.Pack.Config); e != nil {
		return s, e
	}
	if e := s.Pack.Config.validate(); e != nil {
		return s, e
	}
	for _, name := range []string{"organisation.json", "accounts.json"} {
		var raw json.RawMessage
		if e := read(name, &raw); e != nil {
			return s, e
		}
	}
	add := func(name string) (Reports, error) {
		var r Reports
		if e := read(name+".json", &r); e != nil {
			return r, e
		}
		if len(r.Reports) != 1 {
			return r, fmt.Errorf("%s must contain exactly one report", name)
		}
		sheet := Sheet{Name: name, Titles: r.Reports[0].ReportTitles}
		flatten(r.Reports[0].Rows, &sheet.Rows)
		s.Pack.Sheets = append(s.Pack.Sheets, sheet)
		return r, nil
	}
	for _, name := range []string{"TrialBalance", "BalanceSheet", "Accounts-ProfitAndLoss"} {
		if _, e := add(name); e != nil {
			return s, e
		}
	}
	c := s.Pack.Config
	start, _ := date(c.TradingStart)
	end, _ := date(c.To)
	s.Periods = periods(start, end)
	for _, p := range s.Periods {
		r, e := add("ProfitAndLoss-" + p.From + "-" + p.To)
		if e != nil {
			return s, e
		}
		s.Reports = append(s.Reports, r)
	}
	s.Fingerprint = hex.EncodeToString(hash.Sum(nil))
	return s, nil
}
func loadAnswers(path, fingerprint string) (Answers, error) {
	a := Answers{Version: 1, Fingerprint: fingerprint, Values: map[string]string{}}
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return a, nil
	}
	if e != nil {
		return a, e
	}
	if e = decodeStrict(b, &a); e != nil {
		return a, e
	}
	if a.Version != 1 || a.Fingerprint != fingerprint {
		return a, errors.New("saved answers belong to different Xero evidence or a different review version; choose a new --answers file and review again")
	}
	if a.Values == nil {
		a.Values = map[string]string{}
	}
	return a, nil
}

// Ask only for setup fields not already available in the user's config.
func setupSnapshot(state, configPath, data string, t *terminal) error {
	unlock, e := fileLock(configPath + ".lock")
	if e != nil {
		return e
	}
	defer unlock()
	var c Config
	b, e := os.ReadFile(configPath)
	if os.IsNotExist(e) {
		b = []byte(exampleConfig)
	} else if e != nil {
		return e
	}
	if e = decodeStrict(b, &c); e != nil {
		return e
	}
	for _, item := range []struct {
		key   string
		dst   *string
		check func(string) error
	}{
		{"Registered company name", &c.CompanyName, required}, {"Company number", &c.CompanyNumber, required},
		{"Accounts start (YYYY-MM-DD)", &c.From, validDate}, {"Accounts end (YYYY-MM-DD)", &c.To, validDate},
		{"Actual trading start (YYYY-MM-DD)", &c.TradingStart, validDate},
	} {
		if *item.dst == "" {
			v, e := t.ask(question{Text: item.key, Check: item.check})
			if e != nil {
				return e
			}
			*item.dst = v
			if e = atomicJSON(configPath, c); e != nil {
				return e
			}
		}
	}
	unlockState, e := fileLock(filepath.Join(state, "lock"))
	if e != nil {
		return e
	}
	defer unlockState()
	x := newXero(state)
	if e = x.load(); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if c.TenantID == "" {
		connections, e := x.connections(ctx)
		if e != nil {
			return e
		}
		if len(connections) == 0 {
			return errors.New("no Xero organisations authorised; run login")
		}
		fmt.Fprintln(t.out, "Authorised Xero organisations:")
		for i, v := range connections {
			fmt.Fprintf(t.out, "%d. %s (%s)\n", i+1, v.Name, v.ID)
		}
		v, e := t.ask(question{Text: "Choose organisation number", Check: func(s string) error {
			n, e := strconv.Atoi(s)
			if e != nil || n < 1 || n > len(connections) {
				return errors.New("choose one of the listed numbers")
			}
			return nil
		}})
		if e != nil {
			return e
		}
		n, _ := strconv.Atoi(v)
		c.TenantID = connections[n-1].ID
		if e = atomicJSON(configPath, c); e != nil {
			return e
		}
	}
	if e = c.validate(); e != nil {
		return e
	}
	if e = atomicJSON(configPath, c); e != nil {
		return e
	}
	fmt.Fprintln(t.out, "Downloading Xero evidence...")
	return prepare(ctx, x, c, data)
}

func reviewCommand(state, config, data, path string, edit bool, in io.Reader, out io.Writer) error {
	t := newTerminal(in, out)
	if _, e := os.Stat(data); os.IsNotExist(e) {
		if e = setupSnapshot(state, config, data, t); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
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
	// Persist the snapshot association even if the first question is interrupted.
	if e = atomicJSON(path, a); e != nil {
		return e
	}
	fmt.Fprintf(out, "Reviewing %s, %s to %s. Answers save after every question.\n", s.Pack.Config.CompanyName, s.Pack.Config.From, s.Pack.Config.To)
	ask := func(q question) (string, error) {
		if old, ok := a.Values[q.Key]; ok {
			if !edit {
				if e := q.Check(old); e != nil {
					return "", fmt.Errorf("saved %s is invalid; rerun with --edit: %w", q.Key, e)
				}
				return old, nil
			}
			q.Default = old
		}
		v, e := t.ask(q)
		if e != nil {
			return "", e
		}
		a.Values[q.Key] = v
		if e = atomicJSON(path, a); e != nil {
			return "", e
		}
		return v, nil
	}
	result, e := walkReview(s, ask, out)
	if e != nil {
		return e
	}
	if len(result.Blockers) > 0 {
		fmt.Fprintln(out, "Saved. These items still need resolving:")
		for _, b := range result.Blockers {
			fmt.Fprintln(out, "-", b)
		}
	} else {
		fmt.Fprintln(out, "Review saved. Run companytax generate with this --data directory to create the documents.")
	}
	return nil
}

type ReviewResult struct {
	Config   Config
	Facts    map[string]string
	Blockers []string
}

func walkReview(s Snapshot, ask askFunc, out io.Writer) (ReviewResult, error) {
	result := ReviewResult{Config: s.Pack.Config, Facts: map[string]string{}}
	result.Config.Reviews = nil
	result.Config.Ordinary = false
	result.Config.Associated = nil
	// Each successful answer is collected for generation; stale answers to
	// conditional questions are ignored when their parent answer changes.
	get := func(key, text, def string, check func(string) error) (string, error) {
		v, e := ask(question{key, text, def, check})
		if e == nil {
			result.Facts[key] = v
		}
		return v, e
	}
	gates := []struct{ key, text string }{
		{"identity", "Confirm the company, accounts dates and actual trading start shown above are correct (yes/no)"},
		{"periods", "Confirm the suggested Corporation Tax periods match your HMRC record (yes/no)"},
		{"reconciled", "Are the Xero accounts reconciled with year-end accruals, share capital and opening balances checked (yes/no)"},
		{"ordinary", "Is this an ordinary UK-resident trading company eligible for small-profits/marginal relief, not an investment-holding or special-regime company (yes/no)"},
	}
	for _, p := range s.Periods {
		fmt.Fprintf(out, "Suggested tax period: %s to %s\n", p.From, p.To)
	}
	if _, e := get("utr", "Company's 10-digit Corporation Tax UTR (not VAT number)", "", validUTR); e != nil {
		return result, e
	}
	for _, g := range gates {
		v, e := get(g.key, g.text, "", yesNo)
		if e != nil {
			return result, e
		}
		if v == "no" {
			result.Blockers = append(result.Blockers, "Resolve confirmation: "+g.key)
		}
	}
	associated, e := get("associated", "Number of other associated companies (exclude this company)", "", count)
	if e != nil {
		return result, e
	}
	n, _ := strconv.Atoi(associated)
	result.Config.Associated = &n
	stable, e := get("associated_stable", "Was that associated-company count unchanged throughout all tax periods (yes/no)", "", yesNo)
	if e != nil {
		return result, e
	}
	if stable == "no" {
		result.Blockers = append(result.Blockers, "Changing associated-company counts need a period-specific calculation")
	}
	// Reports cannot prove absence of these cases, so ask once rather than
	// assuming a missing account label means the company has no such income.
	for _, g := range []struct{ key, text string }{
		{"other_income", "Any non-trading interest, property income, asset/crypto gains, exempt dividends, or overseas tax relief (yes/no)"},
		{"loss_reliefs", "Any losses to use, group relief, qualifying donations, R&D or other tax credits/claims (yes/no)"},
		{"director_loans", "Any loans or advances by the company to directors/shareholders or their associates during these periods, even if repaid (yes/no)"},
	} {
		v, e := get(g.key, g.text, "", yesNo)
		if e != nil {
			return result, e
		}
		if v == "yes" {
			if _, e = get(g.key+"_details", "Describe the amounts, relevant dates and any repayments/claims", "", required); e != nil {
				return result, e
			}
			result.Blockers = append(result.Blockers, g.key+": additional tax treatment/supplementary pages are required")
		}
	}
	if _, e = get("director", "Name of director who will approve the accounts", "", required); e != nil {
		return result, e
	}
	approved, e := get("approved", "Have the statutory accounts already been approved (yes/no)", "", yesNo)
	if e != nil {
		return result, e
	}
	if approved == "yes" {
		if _, e = get("approval_date", "Actual accounts approval date (YYYY-MM-DD)", "", func(v string) error {
			d, e := date(v)
			if e != nil {
				return e
			}
			end, _ := date(result.Config.To)
			if d.Before(end) || d.After(time.Now().UTC()) {
				return errors.New("approval must be on/after the accounts end and not in the future")
			}
			return nil
		}); e != nil {
			return result, e
		}
	}
	if _, e = get("accounts_notes", "Accounting policies/disclosures or matters still to resolve (enter none if none)", "", required); e != nil {
		return result, e
	}
	for i, p := range s.Periods {
		prefix := p.From + "/"
		rows := s.Reports[i].Reports[0].Rows
		var display [][]string
		flatten(rows, &display)
		fmt.Fprintf(out, "\nProfit and loss: %s to %s (current-period column)\n", p.From, p.To)
		for _, r := range display {
			if len(r) > 1 {
				fmt.Fprintf(out, "  %s: %s\n", r[0], r[1])
			}
		}
		label, e := get(prefix+"profit", "Exact profit row label to use", "Net Profit", func(v string) error { _, e := profit(rows, v); return e })
		if e != nil {
			return result, e
		}
		review := Review{From: p.From, To: p.To, ProfitLabel: label}
		// Suggest obvious book adjustments, but never apply based on the label alone.
		for j, r := range display {
			if len(r) < 2 {
				continue
			}
			name := strings.ToLower(r[0])
			reason := ""
			if strings.Contains(name, "depreciation") {
				reason = "depreciation"
			} else if strings.Contains(name, "corporation tax") || strings.Contains(name, "income tax expense") {
				reason = "booked tax"
			}
			if reason == "" {
				continue
			}
			m, e := money(r[1])
			if e != nil || m.Sign() <= 0 {
				continue
			}
			yes, e := get(prefix+"addback/"+strconv.Itoa(j), fmt.Sprintf("Add back %s GBP shown as %s? Only say yes if deducted in the selected profit (yes/no)", r[1], r[0]), "", yesNo)
			if e != nil {
				return result, e
			}
			if yes == "yes" {
				review.Adjustments = append(review.Adjustments, Adjustment{Reason: "Add back " + r[0], Amount: r[1]})
			}
		}
		extra, e := get(prefix+"adjustment_count", "How many additional tax adjustments (disallowable costs, reviewed capital allowances, etc.)", "", count)
		if e != nil {
			return result, e
		}
		n, _ := strconv.Atoi(extra)
		for j := 0; j < n; j++ {
			key := prefix + "adjustment/" + strconv.Itoa(j) + "/"
			reason, e := get(key+"reason", "Adjustment reason", "", required)
			if e != nil {
				return result, e
			}
			amount, e := get(key+"amount", "Signed GBP adjustment (positive add-back; negative deduction)", "", func(v string) error { _, e := money(v); return e })
			if e != nil {
				return result, e
			}
			review.Adjustments = append(review.Adjustments, Adjustment{reason, amount})
		}
		confirmed, e := get(prefix+"confirmed", "Have all tax adjustments and this period's profit allocation been reviewed, including equipment/capital allowances and pre-trading costs (yes/no)", "", yesNo)
		if e != nil {
			return result, e
		}
		review.Confirmed = confirmed == "yes"
		if !review.Confirmed {
			result.Blockers = append(result.Blockers, p.From+": tax adjustments/allocation not confirmed")
		}
		if _, e = get(prefix+"tax_paid", "Corporation Tax already paid to HMRC for this period (GBP)", "", nonnegative); e != nil {
			return result, e
		}
		result.Config.Reviews = append(result.Config.Reviews, review)
	}
	result.Config.Ordinary = len(result.Blockers) == 0
	return result, result.Config.validate()
}
