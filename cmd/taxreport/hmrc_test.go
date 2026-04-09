package main

import (
	"math"
	"testing"
	"time"
)

func date(y, m, d int) time.Time {
	return time.Date(y, time.Month(m), d, 12, 0, 0, 0, time.UTC)
}

func assertClose(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.01 {
		t.Errorf("%s: got %.2f, want %.2f", name, got, want)
	}
}

func TestSection104Pool(t *testing.T) {
	// Buy 10 BTC at £100 each (total £1000 + no fees for simplicity)
	// Buy 5 BTC at £200 each (total £1000)
	// Sell 8 BTC at £300 each (total £2400)
	//
	// Pool: 15 BTC at £2000 total. Cost per unit = £133.33
	// Sell 8: cost = 8/15 * 2000 = £1066.67
	// Gain = £2400 - £1066.67 = £1333.33

	txns := []Transaction{
		{Date: date(2024, 1, 10), Type: "buy", Asset: "BTC", Quantity: 10, TotalGBP: 1000},
		{Date: date(2024, 2, 15), Type: "buy", Asset: "BTC", Quantity: 5, TotalGBP: 1000},
		{Date: date(2024, 6, 1), Type: "sell", Asset: "BTC", Quantity: 8, TotalGBP: 2400},
	}

	yearStart := time.Date(2024, 4, 6, 0, 0, 0, 0, time.UTC)
	yearEnd := time.Date(2025, 4, 5, 23, 59, 59, 0, time.UTC)

	disposals := calculateCapitalGains(txns, yearStart, yearEnd)

	if len(disposals) != 1 {
		t.Fatalf("expected 1 disposal, got %d", len(disposals))
	}

	d := disposals[0]
	assertClose(t, "proceeds", d.Proceeds, 2400)
	assertClose(t, "cost", d.Cost, 1066.67)
	assertClose(t, "gain", d.Gain, 1333.33)
	if d.Rule != "s104" {
		t.Errorf("rule: got %q, want %q", d.Rule, "s104")
	}
}

func TestSameDayRule(t *testing.T) {
	// Buy 5 BTC at £200 each on day 1
	// Buy 3 BTC at £400 each on day 2 (same day as sell)
	// Sell 3 BTC at £500 each on day 2
	//
	// Same-day rule: match the 3 sold with the 3 bought on day 2
	// Cost = £1200 (3 * £400), Proceeds = £1500 (3 * £500)
	// Gain = £300

	txns := []Transaction{
		{Date: date(2024, 5, 1), Type: "buy", Asset: "BTC", Quantity: 5, TotalGBP: 1000},
		{Date: date(2024, 7, 15), Type: "buy", Asset: "BTC", Quantity: 3, TotalGBP: 1200},
		{Date: date(2024, 7, 15), Type: "sell", Asset: "BTC", Quantity: 3, TotalGBP: 1500},
	}

	yearStart := time.Date(2024, 4, 6, 0, 0, 0, 0, time.UTC)
	yearEnd := time.Date(2025, 4, 5, 23, 59, 59, 0, time.UTC)

	disposals := calculateCapitalGains(txns, yearStart, yearEnd)

	if len(disposals) != 1 {
		t.Fatalf("expected 1 disposal, got %d", len(disposals))
	}

	d := disposals[0]
	assertClose(t, "proceeds", d.Proceeds, 1500)
	assertClose(t, "cost", d.Cost, 1200)
	assertClose(t, "gain", d.Gain, 300)
	if d.Rule != "same-day" {
		t.Errorf("rule: got %q, want %q", d.Rule, "same-day")
	}
}

func TestBedAndBreakfastRule(t *testing.T) {
	// Buy 10 BTC at £100 each on 1 Jan (pool)
	// Sell 5 BTC at £300 each on 1 Jul
	// Rebuy 5 BTC at £280 each on 15 Jul (within 30 days of sell)
	//
	// B&B rule: match the sell with the rebuy
	// Cost = £1400 (5 * £280), Proceeds = £1500 (5 * £300)
	// Gain = £100

	txns := []Transaction{
		{Date: date(2024, 1, 1), Type: "buy", Asset: "BTC", Quantity: 10, TotalGBP: 1000},
		{Date: date(2024, 7, 1), Type: "sell", Asset: "BTC", Quantity: 5, TotalGBP: 1500},
		{Date: date(2024, 7, 15), Type: "buy", Asset: "BTC", Quantity: 5, TotalGBP: 1400},
	}

	yearStart := time.Date(2024, 4, 6, 0, 0, 0, 0, time.UTC)
	yearEnd := time.Date(2025, 4, 5, 23, 59, 59, 0, time.UTC)

	disposals := calculateCapitalGains(txns, yearStart, yearEnd)

	if len(disposals) != 1 {
		t.Fatalf("expected 1 disposal, got %d", len(disposals))
	}

	d := disposals[0]
	assertClose(t, "proceeds", d.Proceeds, 1500)
	assertClose(t, "cost", d.Cost, 1400)
	assertClose(t, "gain", d.Gain, 100)
	if d.Rule != "30-day" {
		t.Errorf("rule: got %q, want %q", d.Rule, "30-day")
	}
}

func TestBedAndBreakfastPartialMatch(t *testing.T) {
	// Buy 10 BTC at £100 each (pool: 10 BTC, £1000)
	// Sell 5 BTC at £300 each
	// Rebuy 2 BTC at £280 each within 30 days
	//
	// 2 BTC matched by B&B (cost £560), 3 BTC from pool (cost = 3/10 * 1000 = £300)
	// Total cost = £860
	// Proceeds = £1500
	// Gain = £640

	txns := []Transaction{
		{Date: date(2024, 1, 1), Type: "buy", Asset: "BTC", Quantity: 10, TotalGBP: 1000},
		{Date: date(2024, 7, 1), Type: "sell", Asset: "BTC", Quantity: 5, TotalGBP: 1500},
		{Date: date(2024, 7, 10), Type: "buy", Asset: "BTC", Quantity: 2, TotalGBP: 560},
	}

	yearStart := time.Date(2024, 4, 6, 0, 0, 0, 0, time.UTC)
	yearEnd := time.Date(2025, 4, 5, 23, 59, 59, 0, time.UTC)

	disposals := calculateCapitalGains(txns, yearStart, yearEnd)

	if len(disposals) != 1 {
		t.Fatalf("expected 1 disposal, got %d", len(disposals))
	}

	d := disposals[0]
	assertClose(t, "proceeds", d.Proceeds, 1500)
	assertClose(t, "cost", d.Cost, 860)
	assertClose(t, "gain", d.Gain, 640)
	if d.Rule != "30-day+s104" {
		t.Errorf("rule: got %q, want %q", d.Rule, "30-day+s104")
	}
}

func TestMultipleAssets(t *testing.T) {
	txns := []Transaction{
		{Date: date(2024, 1, 1), Type: "buy", Asset: "BTC", Quantity: 1, TotalGBP: 30000},
		{Date: date(2024, 1, 1), Type: "buy", Asset: "ETH", Quantity: 10, TotalGBP: 20000},
		{Date: date(2024, 8, 1), Type: "sell", Asset: "BTC", Quantity: 1, TotalGBP: 40000},
		{Date: date(2024, 8, 1), Type: "sell", Asset: "ETH", Quantity: 10, TotalGBP: 25000},
	}

	yearStart := time.Date(2024, 4, 6, 0, 0, 0, 0, time.UTC)
	yearEnd := time.Date(2025, 4, 5, 23, 59, 59, 0, time.UTC)

	disposals := calculateCapitalGains(txns, yearStart, yearEnd)

	if len(disposals) != 2 {
		t.Fatalf("expected 2 disposals, got %d", len(disposals))
	}

	totalGain := 0.0
	for _, d := range disposals {
		totalGain += d.Gain
	}
	assertClose(t, "total gain", totalGain, 15000) // 10000 + 5000
}

func TestDisposalOutsideTaxYear(t *testing.T) {
	// Disposal before tax year should not appear
	txns := []Transaction{
		{Date: date(2024, 1, 1), Type: "buy", Asset: "BTC", Quantity: 1, TotalGBP: 1000},
		{Date: date(2024, 3, 1), Type: "sell", Asset: "BTC", Quantity: 1, TotalGBP: 2000},
	}

	yearStart := time.Date(2024, 4, 6, 0, 0, 0, 0, time.UTC)
	yearEnd := time.Date(2025, 4, 5, 23, 59, 59, 0, time.UTC)

	disposals := calculateCapitalGains(txns, yearStart, yearEnd)

	if len(disposals) != 0 {
		t.Fatalf("expected 0 disposals, got %d", len(disposals))
	}
}

func TestPoolCarriesAcrossTaxYears(t *testing.T) {
	// Acquisitions from previous years should be in the S104 pool
	txns := []Transaction{
		{Date: date(2022, 6, 1), Type: "buy", Asset: "BTC", Quantity: 5, TotalGBP: 5000},
		{Date: date(2023, 6, 1), Type: "buy", Asset: "BTC", Quantity: 5, TotalGBP: 10000},
		{Date: date(2024, 8, 1), Type: "sell", Asset: "BTC", Quantity: 4, TotalGBP: 8000},
	}

	yearStart := time.Date(2024, 4, 6, 0, 0, 0, 0, time.UTC)
	yearEnd := time.Date(2025, 4, 5, 23, 59, 59, 0, time.UTC)

	disposals := calculateCapitalGains(txns, yearStart, yearEnd)

	if len(disposals) != 1 {
		t.Fatalf("expected 1 disposal, got %d", len(disposals))
	}

	// Pool: 10 BTC at £15,000. Cost per unit = £1,500
	// Sell 4: cost = 4/10 * 15000 = £6,000
	// Gain = £8,000 - £6,000 = £2,000
	d := disposals[0]
	assertClose(t, "cost", d.Cost, 6000)
	assertClose(t, "gain", d.Gain, 2000)
}

func TestLoss(t *testing.T) {
	txns := []Transaction{
		{Date: date(2024, 1, 1), Type: "buy", Asset: "BTC", Quantity: 1, TotalGBP: 50000},
		{Date: date(2024, 8, 1), Type: "sell", Asset: "BTC", Quantity: 1, TotalGBP: 30000},
	}

	yearStart := time.Date(2024, 4, 6, 0, 0, 0, 0, time.UTC)
	yearEnd := time.Date(2025, 4, 5, 23, 59, 59, 0, time.UTC)

	disposals := calculateCapitalGains(txns, yearStart, yearEnd)

	if len(disposals) != 1 {
		t.Fatalf("expected 1 disposal, got %d", len(disposals))
	}

	d := disposals[0]
	assertClose(t, "gain", d.Gain, -20000)
}

func TestKrakenPairParsing(t *testing.T) {
	tests := []struct {
		pair       string
		wantBase   string
		wantQuote  string
	}{
		{"XXBTZGBP", "BTC", "GBP"},
		{"XETHZGBP", "ETH", "GBP"},
		{"ADAGBP", "ADA", "GBP"},
		{"DOTGBP", "DOT", "GBP"},
		{"SOLGBP", "SOL", "GBP"},
		{"XXBTZUSD", "BTC", "USD"},
		{"XETHXXBT", "ETH", "BTC"},
		{"MATICGBP", "MATIC", "GBP"},
		{"BNBUSDT", "BNB", "USDT"},
		{"ETHUSDC", "ETH", "USDC"},
	}

	for _, tt := range tests {
		base, quote := parseKrakenPair(tt.pair)
		if base != tt.wantBase || quote != tt.wantQuote {
			t.Errorf("parseKrakenPair(%q) = (%q, %q), want (%q, %q)",
				tt.pair, base, quote, tt.wantBase, tt.wantQuote)
		}
	}
}

func TestCryptoToCryptoTrade(t *testing.T) {
	// Simulate: buy 100 USDT for £79, then trade USDT for BNB, then sell BNB for GBP
	// USD/GBP rate = 0.79
	//
	// Buy 100 USDT at £79 total
	// Buy 10 BNB with 100 USDT (cost=100, fee=0) at rate 0.80
	//   -> BNB acquisition: 10 BNB at £80
	//   -> USDT disposal: 100 USDT, proceeds £80
	// Sell 10 BNB for £120 GBP
	//
	// USDT gain: £80 - £79 = £1
	// BNB gain: £120 - £80 = £40
	// Total: £41

	txns := []Transaction{
		{Date: date(2024, 1, 1), Type: "buy", Asset: "USDT", Quantity: 100, TotalGBP: 79},
		// BNB/USDT buy creates two transactions:
		{Date: date(2024, 6, 1), Type: "buy", Asset: "BNB", Quantity: 10, TotalGBP: 80},
		{Date: date(2024, 6, 1), Type: "sell", Asset: "USDT", Quantity: 100, TotalGBP: 80},
		// Sell BNB for GBP
		{Date: date(2024, 9, 1), Type: "sell", Asset: "BNB", Quantity: 10, TotalGBP: 120},
	}

	yearStart := time.Date(2024, 4, 6, 0, 0, 0, 0, time.UTC)
	yearEnd := time.Date(2025, 4, 5, 23, 59, 59, 0, time.UTC)

	disposals := calculateCapitalGains(txns, yearStart, yearEnd)

	// Should have 2 disposals in tax year: USDT and BNB
	if len(disposals) != 2 {
		t.Fatalf("expected 2 disposals, got %d", len(disposals))
	}

	totalGain := 0.0
	for _, d := range disposals {
		totalGain += d.Gain
	}
	assertClose(t, "total gain", totalGain, 41)
}

func TestExchangeRatesFixed(t *testing.T) {
	rates := NewExchangeRates()
	rates.SetFixedRate("USD", 0.79)

	// Direct USD
	gbp, ok := rates.ToGBP(100, "USD", date(2024, 6, 1))
	if !ok {
		t.Fatal("expected rate for USD")
	}
	assertClose(t, "USD to GBP", gbp, 79)

	// USDT maps to USD
	gbp, ok = rates.ToGBP(100, "USDT", date(2024, 6, 1))
	if !ok {
		t.Fatal("expected rate for USDT")
	}
	assertClose(t, "USDT to GBP", gbp, 79)

	// USDC maps to USD
	gbp, ok = rates.ToGBP(100, "USDC", date(2024, 6, 1))
	if !ok {
		t.Fatal("expected rate for USDC")
	}
	assertClose(t, "USDC to GBP", gbp, 79)

	// GBP returns as-is
	gbp, ok = rates.ToGBP(100, "GBP", date(2024, 6, 1))
	if !ok {
		t.Fatal("expected rate for GBP")
	}
	assertClose(t, "GBP to GBP", gbp, 100)

	// Unknown currency
	_, ok = rates.ToGBP(100, "BTC", date(2024, 6, 1))
	if ok {
		t.Fatal("expected no rate for BTC")
	}
}

func TestExchangeRatesDaily(t *testing.T) {
	rates := NewExchangeRates()
	rates.daily["USD"] = []dateRate{
		{date: date(2024, 1, 1), rate: 0.78},
		{date: date(2024, 6, 1), rate: 0.80},
		{date: date(2024, 12, 1), rate: 0.82},
	}

	// Exact date match
	gbp, ok := rates.ToGBP(100, "USD", date(2024, 6, 1))
	if !ok {
		t.Fatal("expected rate")
	}
	assertClose(t, "exact date", gbp, 80)

	// Between dates - uses earlier rate
	gbp, _ = rates.ToGBP(100, "USD", date(2024, 8, 15))
	assertClose(t, "between dates", gbp, 80)

	// After all dates - uses latest
	gbp, _ = rates.ToGBP(100, "USD", date(2025, 3, 1))
	assertClose(t, "after all dates", gbp, 82)

	// USDT uses USD rate
	gbp, _ = rates.ToGBP(100, "USDT", date(2024, 6, 1))
	assertClose(t, "USDT daily", gbp, 80)
}
