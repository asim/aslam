package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ExchangeRates provides GBP conversion for non-GBP trade currencies.
type ExchangeRates struct {
	daily map[string][]dateRate // currency -> sorted (date, rate) pairs
	fixed map[string]float64   // currency -> fixed rate
}

type dateRate struct {
	date time.Time
	rate float64
}

func NewExchangeRates() *ExchangeRates {
	return &ExchangeRates{
		daily: make(map[string][]dateRate),
		fixed: make(map[string]float64),
	}
}

func (r *ExchangeRates) SetFixedRate(currency string, rate float64) {
	r.fixed[strings.ToUpper(currency)] = rate
}

// LoadCSV loads daily rates from a CSV file.
// Format: date,USD,EUR (header names = currency codes, values = GBP per unit)
func (r *ExchangeRates) LoadCSV(filepath string) error {
	f, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("reading rates CSV: %w", err)
	}

	if len(records) < 2 {
		return fmt.Errorf("rates file needs a header and at least one data row")
	}

	header := records[0]
	currencies := make([]string, len(header)-1)
	for i := 1; i < len(header); i++ {
		currencies[i-1] = strings.TrimSpace(strings.ToUpper(header[i]))
	}

	for _, row := range records[1:] {
		if len(row) == 0 || strings.TrimSpace(row[0]) == "" {
			continue
		}
		d, err := time.Parse("2006-01-02", strings.TrimSpace(row[0]))
		if err != nil {
			continue
		}
		for i, curr := range currencies {
			if i+1 < len(row) {
				rate, err := parseNumber(row[i+1])
				if err != nil || rate <= 0 {
					continue
				}
				r.daily[curr] = append(r.daily[curr], dateRate{date: d, rate: rate})
			}
		}
	}

	for curr := range r.daily {
		sort.Slice(r.daily[curr], func(i, j int) bool {
			return r.daily[curr][i].date.Before(r.daily[curr][j].date)
		})
	}
	return nil
}

// stablecoinBase maps stablecoin tickers to their underlying fiat currency.
var stablecoinBase = map[string]string{
	"USDT": "USD", "USDC": "USD", "DAI": "USD",
	"BUSD": "USD", "TUSD": "USD", "GUSD": "USD",
	"PYUSD": "USD", "EURT": "EUR",
}

// ToGBP converts amount from the given currency to GBP.
// Returns (gbpAmount, true) on success, (0, false) if no rate available.
func (r *ExchangeRates) ToGBP(amount float64, currency string, date time.Time) (float64, bool) {
	currency = strings.ToUpper(currency)
	if currency == "GBP" {
		return amount, true
	}

	lookup := currency
	if fiat, ok := stablecoinBase[currency]; ok {
		lookup = fiat
	}

	if rate, ok := r.fixed[lookup]; ok {
		return amount * rate, true
	}

	rates, ok := r.daily[lookup]
	if !ok || len(rates) == 0 {
		return 0, false
	}

	// Find latest rate on or before the given date
	idx := sort.Search(len(rates), func(i int) bool {
		return rates[i].date.After(date)
	})
	if idx > 0 {
		return amount * rates[idx-1].rate, true
	}
	return amount * rates[0].rate, true
}

func (r *ExchangeRates) HasRate(currency string) bool {
	currency = strings.ToUpper(currency)
	if currency == "GBP" {
		return true
	}
	lookup := currency
	if fiat, ok := stablecoinBase[currency]; ok {
		lookup = fiat
	}
	if _, ok := r.fixed[lookup]; ok {
		return true
	}
	rates, ok := r.daily[lookup]
	return ok && len(rates) > 0
}

var fiatCurrencies = map[string]bool{
	"GBP": true, "USD": true, "EUR": true, "JPY": true,
	"CAD": true, "AUD": true, "CHF": true, "NZD": true,
	"SEK": true, "NOK": true, "DKK": true, "SGD": true,
	"HKD": true, "KRW": true, "CNY": true, "INR": true,
	"BRL": true, "MXN": true, "ZAR": true, "TRY": true,
}

func isFiat(currency string) bool {
	return fiatCurrencies[strings.ToUpper(currency)]
}
