package main

import "time"

// Transaction represents a normalized buy or sell event from any exchange.
type Transaction struct {
	Date     time.Time
	Type     string  // "buy" or "sell"
	Asset    string  // normalized symbol, e.g. "BTC", "ETH"
	Quantity float64
	TotalGBP float64 // buy: total cost incl fees; sell: net proceeds after fees
	FeeGBP   float64
	Source   string // "coinbase" or "kraken"
	Notes    string
}

// DisposalEvent represents a taxable disposal for HMRC reporting.
type DisposalEvent struct {
	Date     time.Time
	Asset    string
	Quantity float64
	Proceeds float64 // GBP received (net of disposal fees)
	Cost     float64 // allowable cost in GBP
	Gain     float64 // Proceeds - Cost
	Rule     string  // matching rule(s) applied: "same-day", "30-day", "s104", or combination
}
