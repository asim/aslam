package main

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"strings"
)

// parseManual reads a simple user-created CSV for transactions not captured
// by exchange exports (e.g. purchases from email receipts, OTC trades).
//
// Format:
//
//	date,type,asset,quantity,total_gbp,notes
//	2024-03-15,buy,BTC,0.5,15000,Original purchase from Binance
//	2023-01-10,buy,BNB,30,3000,Purchased on Binance
func parseManual(filepath string) ([]Transaction, []string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1
	reader.Comment = '#'

	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("reading CSV: %w", err)
	}

	if len(records) < 2 {
		return nil, nil, fmt.Errorf("file needs a header row and at least one data row")
	}

	// Map header columns
	cols := map[string]int{}
	for i, name := range records[0] {
		cols[strings.TrimSpace(strings.ToLower(name))] = i
	}

	required := []string{"date", "type", "asset", "quantity", "total_gbp"}
	for _, r := range required {
		if _, ok := cols[r]; !ok {
			return nil, nil, fmt.Errorf("missing required column: %q (expected: date,type,asset,quantity,total_gbp,notes)", r)
		}
	}

	dateCol := cols["date"]
	typeCol := cols["type"]
	assetCol := cols["asset"]
	qtyCol := cols["quantity"]
	gbpCol := cols["total_gbp"]
	notesCol, hasNotes := cols["notes"]

	var txns []Transaction
	var warnings []string

	for i := 1; i < len(records); i++ {
		row := records[i]
		maxCol := max(dateCol, typeCol, assetCol, qtyCol, gbpCol)
		if len(row) <= maxCol {
			continue
		}

		ts, err := parseTimestamp(strings.TrimSpace(row[dateCol]))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Manual line %d: bad date %q", i+1, row[dateCol]))
			continue
		}

		txType := strings.TrimSpace(strings.ToLower(row[typeCol]))
		if txType != "buy" && txType != "sell" {
			warnings = append(warnings, fmt.Sprintf("Manual line %d: type must be 'buy' or 'sell', got %q", i+1, row[typeCol]))
			continue
		}

		asset := strings.TrimSpace(strings.ToUpper(row[assetCol]))
		qty, err := parseNumber(row[qtyCol])
		if err != nil || qty == 0 {
			warnings = append(warnings, fmt.Sprintf("Manual line %d: invalid quantity %q", i+1, row[qtyCol]))
			continue
		}
		qty = math.Abs(qty)

		totalGBP, err := parseNumber(row[gbpCol])
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Manual line %d: invalid total_gbp %q", i+1, row[gbpCol]))
			continue
		}
		totalGBP = math.Abs(totalGBP)

		var notes string
		if hasNotes && len(row) > notesCol {
			notes = strings.TrimSpace(row[notesCol])
		}

		txns = append(txns, Transaction{
			Date: ts, Type: txType, Asset: asset, Quantity: qty,
			TotalGBP: totalGBP, FeeGBP: 0, Source: "manual", Notes: notes,
		})
	}

	return txns, warnings, nil
}
