package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func snapshotFixture(t *testing.T) (string, Snapshot) {
	t.Helper()
	dir := t.TempDir()
	c := reviewed()
	c.To = "2026-07-24"
	if e := saveJSON(filepath.Join(dir, "company.json"), c); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"organisation.json", "accounts.json"} {
		if e := saveJSON(filepath.Join(dir, name), map[string]any{}); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"TrialBalance", "BalanceSheet", "Accounts-ProfitAndLoss", "ProfitAndLoss-2025-07-25-2026-07-24"} {
		if e := saveJSON(filepath.Join(dir, name+".json"), fixtureProfit("10000")); e != nil {
			t.Fatal(e)
		}
	}
	s, e := loadSnapshot(dir)
	if e != nil {
		t.Fatal(e)
	}
	return dir, s
}
func allAnswers(s Snapshot) Answers {
	return Answers{Version: 1, Fingerprint: s.Fingerprint, Values: map[string]string{
		"utr": "1234567890", "identity": "yes", "periods": "yes", "reconciled": "yes", "ordinary": "yes", "associated": "0", "associated_stable": "yes",
		"other_income": "no", "loss_reliefs": "no", "director_loans": "no", "director": "Test Director", "approved": "no", "accounts_notes": "none",
		"2025-07-25/profit": "Net Profit", "2025-07-25/adjustment_count": "0", "2025-07-25/confirmed": "yes", "2025-07-25/tax_paid": "100.00",
	}}
}

func TestReviewInterruptResumeAndOfflineGenerate(t *testing.T) {
	data, s := snapshotFixture(t)
	a := allAnswers(s)
	var log bytes.Buffer
	path := filepath.Join(data, "review.json")
	e := reviewCommand("unused", "unused", data, path, false, strings.NewReader("1234567890\nyes\n"), &log)
	if e == nil || !strings.Contains(e.Error(), "paused") {
		t.Fatal(e)
	}
	saved, e := loadAnswers(path, s.Fingerprint)
	if e != nil {
		t.Fatal(e)
	}
	if len(saved.Values) != 2 || saved.Values["utr"] != "1234567890" {
		t.Fatal(saved)
	}
	// Discover the remaining questions using the same traversal as generation,
	// then answer via the terminal. This also checks checkpointed answers are skipped.
	var input strings.Builder
	_, e = walkReview(s, func(q question) (string, error) {
		v, ok := a.Values[q.Key]
		if !ok {
			return "", errors.New("unexpected question " + q.Key)
		}
		if _, done := saved.Values[q.Key]; !done {
			input.WriteString(v + "\n")
		}
		return v, nil
	}, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	log.Reset()
	if e = reviewCommand("unused", "unused", data, path, false, strings.NewReader(input.String()), &log); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(log.String(), "10-digit") {
		t.Fatal("asked UTR again")
	}
	saved, e = loadAnswers(path, s.Fingerprint)
	if e != nil {
		t.Fatal(e)
	}
	if len(saved.Values) != len(a.Values) {
		t.Fatalf("saved %d answers, wanted %d", len(saved.Values), len(a.Values))
	}
	st, e := os.Stat(path)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("review permissions", e)
	}
	out := filepath.Join(t.TempDir(), "return")
	if e = generateCommand(data, path, out); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(out, "return-data.json"))
	if e != nil {
		t.Fatal(e)
	}
	var ret ReturnData
	if e = json.Unmarshal(b, &ret); e != nil {
		t.Fatal(e)
	}
	if ret.UTR != "1234567890" || ret.Periods[0].Balance != "1800.00" || ret.FilingReady {
		t.Fatal(ret)
	}
	if e = generateCommand(data, path, out); e == nil {
		t.Fatal("overwrote generated output")
	}
}

func TestReviewInvalidAndUnsupportedAnswersBlock(t *testing.T) {
	_, s := snapshotFixture(t)
	for _, tc := range []struct{ key, value string }{{"utr", ""}, {"ordinary", "no"}, {"associated", "-1"}, {"other_income", "yes"}, {"2025-07-25/confirmed", "no"}, {"approved", "yes"}} {
		t.Run(tc.key, func(t *testing.T) {
			a := allAnswers(s)
			a.Values[tc.key] = tc.value
			out := filepath.Join(t.TempDir(), "return")
			if e := generateReviewed(s, a, out); e == nil {
				t.Fatal("should block")
			}
			if _, e := os.Stat(out); !os.IsNotExist(e) {
				t.Fatal("output published on failure")
			}
		})
	}
}
func TestReviewSnapshotBinding(t *testing.T) {
	data, s := snapshotFixture(t)
	path := filepath.Join(data, "review.json")
	if e := atomicJSON(path, allAnswers(s)); e != nil {
		t.Fatal(e)
	}
	if e := atomicJSON(filepath.Join(data, "ProfitAndLoss-2025-07-25-2026-07-24.json"), fixtureProfit("20000")); e != nil {
		t.Fatal(e)
	}
	s2, e := loadSnapshot(data)
	if e != nil {
		t.Fatal(e)
	}
	if s.Fingerprint == s2.Fingerprint {
		t.Fatal("changed source undetected")
	}
	if _, e = loadAnswers(path, s2.Fingerprint); e == nil {
		t.Fatal("stale answers accepted")
	}
}
func TestEditIgnoresStaleConditionalAnswers(t *testing.T) {
	_, s := snapshotFixture(t)
	a := allAnswers(s)
	a.Values["director_loans_details"] = "Old loan detail"
	out := filepath.Join(t.TempDir(), "return")
	if e := generateReviewed(s, a, out); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(out, "return-data.json"))
	if bytes.Contains(b, []byte("Old loan detail")) {
		t.Fatal("inactive answer leaked into output")
	}
}
func TestTerminalValidationAndNoSilentDefault(t *testing.T) {
	var out bytes.Buffer
	tui := newTerminal(strings.NewReader("\ny\nyes\n"), &out)
	got, e := tui.ask(question{Text: "Confirm", Check: yesNo})
	if e != nil || got != "yes" {
		t.Fatal(got, e)
	}
	if strings.Count(out.String(), "enter yes or no") != 2 {
		t.Fatal(out.String())
	}
}
func TestReviewSuggestedAddbackRequiresConfirmation(t *testing.T) {
	_, s := snapshotFixture(t)
	var r Reports
	json.Unmarshal([]byte(`{"Reports":[{"Rows":[{"Cells":[{"Value":"Depreciation"},{"Value":"500.00"}]},{"Cells":[{"Value":"Net Profit"},{"Value":"10000.00"}]}]}]}`), &r)
	s.Reports[0] = r
	for _, answer := range []string{"yes", "no"} {
		a := allAnswers(s)
		result, e := walkReview(s, func(q question) (string, error) {
			if strings.Contains(q.Key, "/addback/") {
				return answer, nil
			}
			return a.Values[q.Key], nil
		}, io.Discard)
		if e != nil {
			t.Fatal(e)
		}
		want := 0
		if answer == "yes" {
			want = 1
		}
		if len(result.Config.Reviews[0].Adjustments) != want {
			t.Fatal("incorrect adjustment")
		}
	}
}
