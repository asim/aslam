package main

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func parseCoinbase(filepath string, rates *ExchangeRates) ([]Transaction, []string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("reading CSV: %w", err)
	}

	// Find header row - skip metadata rows at the top
	headerIdx := -1
	for i, row := range records {
		if len(row) < 2 {
			continue
		}
		first := strings.TrimSpace(strings.TrimPrefix(row[0], "\xef\xbb\xbf"))
		if strings.EqualFold(first, "timestamp") || strings.EqualFold(first, "id") {
			headerIdx = i
			break
		}
		// Also detect Coinbase Pro/Advanced format
		if strings.EqualFold(first, "portfolio") {
			headerIdx = i
			break
		}
	}
	if headerIdx == -1 {
		return nil, nil, fmt.Errorf("could not find header row (expected Timestamp or ID column)")
	}

	// Map column names to indices
	cols := map[string]int{}
	for i, name := range records[headerIdx] {
		key := strings.TrimSpace(strings.ToLower(strings.TrimPrefix(name, "\xef\xbb\xbf")))
		cols[key] = i
	}

	// Detect format
	if _, ok := cols["portfolio"]; ok {
		return parseCoinbasePro(records, headerIdx, cols, rates)
	}
	return parseCoinbaseStandard(records, headerIdx, cols, rates)
}

func parseCoinbaseStandard(records [][]string, headerIdx int, cols map[string]int, rates *ExchangeRates) ([]Transaction, []string, error) {
	required := []string{"timestamp", "transaction type", "asset", "quantity transacted"}
	for _, r := range required {
		if _, ok := cols[r]; !ok {
			return nil, nil, fmt.Errorf("missing required column: %q", r)
		}
	}

	tsCol := cols["timestamp"]
	typeCol := cols["transaction type"]
	assetCol := cols["asset"]
	qtyCol := cols["quantity transacted"]

	subtotalCol, hasSubtotal := cols["subtotal"]
	totalCol, hasTotal := cols["total (inclusive of fees and/or spread)"]
	if !hasTotal {
		totalCol, hasTotal = cols["total"]
	}
	feeCol, hasFee := cols["fees and/or spread"]
	if !hasFee {
		feeCol, hasFee = cols["fees"]
	}
	// Handle column name variations across Coinbase export versions
	spotCol, hasSpot := cols["spot price at transaction"]
	if !hasSpot {
		spotCol, hasSpot = cols["price at transaction"]
	}
	spotCurrCol, hasSpotCurr := cols["spot price currency"]
	if !hasSpotCurr {
		spotCurrCol, hasSpotCurr = cols["price currency"]
	}
	notesCol, hasNotes := cols["notes"]

	convertRe := regexp.MustCompile(`(?i)([\d,.]+)\s+(\w+)\s+to\s+([\d,.]+)\s+(\w+)`)

	var txns []Transaction
	var warnings []string

	for i := headerIdx + 1; i < len(records); i++ {
		row := records[i]
		maxCol := max(tsCol, typeCol, assetCol, qtyCol)
		if len(row) <= maxCol {
			continue
		}

		txType := strings.TrimSpace(row[typeCol])
		asset := strings.TrimSpace(strings.ToUpper(row[assetCol]))

		txTypeLower := strings.ToLower(txType)
		switch txTypeLower {
		case "buy", "sell", "convert",
			"advanced trade buy", "advanced trade sell":
		default:
			if txType != "" {
				warnings = append(warnings, fmt.Sprintf("Coinbase line %d: skipped %q for %s", i+1, txType, asset))
			}
			continue
		}

		qty, err := parseNumber(row[qtyCol])
		if err != nil || qty == 0 {
			warnings = append(warnings, fmt.Sprintf("Coinbase line %d: invalid quantity %q", i+1, row[qtyCol]))
			continue
		}
		qty = math.Abs(qty)

		ts, err := parseTimestamp(strings.TrimSpace(row[tsCol]))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Coinbase line %d: bad timestamp %q", i+1, row[tsCol]))
			continue
		}

		// Determine the currency and GBP values
		currency := "GBP"
		if hasSpotCurr && len(row) > spotCurrCol {
			c := strings.TrimSpace(strings.ToUpper(row[spotCurrCol]))
			if c != "" {
				currency = c
			}
		}

		var totalRaw, feeRaw float64
		if hasTotal && len(row) > totalCol {
			totalRaw, _ = parseNumber(row[totalCol])
		} else if hasSubtotal && len(row) > subtotalCol {
			totalRaw, _ = parseNumber(row[subtotalCol])
		} else if hasSpot && len(row) > spotCol {
			spot, _ := parseNumber(row[spotCol])
			totalRaw = qty * spot
		}
		totalRaw = math.Abs(totalRaw)

		if hasFee && len(row) > feeCol {
			feeRaw, _ = parseNumber(row[feeCol])
			feeRaw = math.Abs(feeRaw)
		}

		// Convert to GBP if needed
		var totalGBP, feeGBP float64
		if currency == "GBP" {
			totalGBP = totalRaw
			feeGBP = feeRaw
		} else if rates.HasRate(currency) {
			totalGBP, _ = rates.ToGBP(totalRaw, currency, ts)
			feeGBP, _ = rates.ToGBP(feeRaw, currency, ts)
		} else {
			warnings = append(warnings, fmt.Sprintf(
				"Coinbase line %d: no rate for %s - skipped. Use --usd-gbp or --rates",
				i+1, currency))
			continue
		}

		var notes string
		if hasNotes && len(row) > notesCol {
			notes = strings.TrimSpace(row[notesCol])
		}

		switch txTypeLower {
		case "buy", "advanced trade buy":
			txns = append(txns, Transaction{
				Date: ts, Type: "buy", Asset: asset, Quantity: qty,
				TotalGBP: totalGBP, FeeGBP: feeGBP, Source: "coinbase", Notes: notes,
			})
		case "sell", "advanced trade sell":
			txns = append(txns, Transaction{
				Date: ts, Type: "sell", Asset: asset, Quantity: qty,
				TotalGBP: totalGBP, FeeGBP: feeGBP, Source: "coinbase", Notes: notes,
			})
		case "convert":
			// Disposal of the FROM asset
			txns = append(txns, Transaction{
				Date: ts, Type: "sell", Asset: asset, Quantity: qty,
				TotalGBP: totalGBP, FeeGBP: feeGBP, Source: "coinbase",
				Notes: fmt.Sprintf("Convert: %s", notes),
			})
			// Try to parse the TO side from notes
			if m := convertRe.FindStringSubmatch(notes); m != nil {
				toQty, _ := strconv.ParseFloat(strings.ReplaceAll(m[3], ",", ""), 64)
				toAsset := strings.ToUpper(m[4])
				if toQty > 0 && toAsset != "" {
					txns = append(txns, Transaction{
						Date: ts, Type: "buy", Asset: toAsset, Quantity: toQty,
						TotalGBP: totalGBP, FeeGBP: 0, Source: "coinbase",
						Notes: fmt.Sprintf("Convert from %s: %s", asset, notes),
					})
				}
			} else {
				warnings = append(warnings, fmt.Sprintf("Coinbase line %d: could not parse Convert destination from notes %q", i+1, notes))
			}
		}
	}

	return txns, warnings, nil
}

func parseCoinbasePro(records [][]string, headerIdx int, cols map[string]int, rates *ExchangeRates) ([]Transaction, []string, error) {
	required := []string{"product", "side", "created at", "size", "price", "fee", "total"}
	for _, r := range required {
		if _, ok := cols[r]; !ok {
			return nil, nil, fmt.Errorf("missing required column for Coinbase Pro format: %q", r)
		}
	}

	productCol := cols["product"]
	sideCol := cols["side"]
	timeCol := cols["created at"]
	sizeCol := cols["size"]
	feeCol := cols["fee"]
	totalCol := cols["total"]

	unitCol, hasUnit := cols["price/fee/total unit"]

	var txns []Transaction
	var warnings []string

	for i := headerIdx + 1; i < len(records); i++ {
		row := records[i]
		maxCol := max(productCol, sideCol, timeCol, sizeCol, feeCol, totalCol)
		if len(row) <= maxCol {
			continue
		}

		product := strings.TrimSpace(row[productCol])
		parts := strings.SplitN(product, "-", 2)
		if len(parts) != 2 {
			warnings = append(warnings, fmt.Sprintf("Coinbase Pro line %d: unrecognized product %q", i+1, product))
			continue
		}
		base := strings.ToUpper(parts[0])
		quote := strings.ToUpper(parts[1])

		if hasUnit && len(row) > unitCol {
			u := strings.TrimSpace(strings.ToUpper(row[unitCol]))
			if u != "" {
				quote = u
			}
		}

		side := strings.TrimSpace(strings.ToLower(row[sideCol]))
		if side != "buy" && side != "sell" {
			continue
		}

		qty, _ := parseNumber(row[sizeCol])
		fee, _ := parseNumber(row[feeCol])
		total, _ := parseNumber(row[totalCol])
		qty = math.Abs(qty)
		fee = math.Abs(fee)
		total = math.Abs(total)

		ts, err := parseTimestamp(strings.TrimSpace(row[timeCol]))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Coinbase Pro line %d: bad timestamp", i+1))
			continue
		}

		if quote == "GBP" {
			// Direct GBP pair
			txns = append(txns, Transaction{
				Date: ts, Type: side, Asset: base, Quantity: qty,
				TotalGBP: total, FeeGBP: fee, Source: "coinbase",
				Notes: fmt.Sprintf("product=%s", product),
			})
			continue
		}

		// Non-GBP quote currency - convert
		if !rates.HasRate(quote) {
			warnings = append(warnings, fmt.Sprintf(
				"Coinbase Pro line %d: no rate for %s (product %s) - skipped. Use --usd-gbp or --rates",
				i+1, quote, product))
			continue
		}

		totalGBP, _ := rates.ToGBP(total, quote, ts)
		feeGBP, _ := rates.ToGBP(fee, quote, ts)

		if side == "buy" {
			// Buying base with quote
			txns = append(txns, Transaction{
				Date: ts, Type: "buy", Asset: base, Quantity: qty,
				TotalGBP: totalGBP, FeeGBP: feeGBP, Source: "coinbase",
				Notes: fmt.Sprintf("product=%s, cost=%.4f %s", product, total, quote),
			})
			if !isFiat(quote) {
				txns = append(txns, Transaction{
					Date: ts, Type: "sell", Asset: quote, Quantity: total,
					TotalGBP: totalGBP, FeeGBP: 0, Source: "coinbase",
					Notes: fmt.Sprintf("product=%s, exchanged for %s", product, base),
				})
			}
		} else {
			// Selling base for quote
			txns = append(txns, Transaction{
				Date: ts, Type: "sell", Asset: base, Quantity: qty,
				TotalGBP: totalGBP, FeeGBP: feeGBP, Source: "coinbase",
				Notes: fmt.Sprintf("product=%s, received=%.4f %s", product, total, quote),
			})
			if !isFiat(quote) {
				netQuote := total // net quote received (total already accounts for fees in Pro format)
				txns = append(txns, Transaction{
					Date: ts, Type: "buy", Asset: quote, Quantity: netQuote,
					TotalGBP: totalGBP, FeeGBP: 0, Source: "coinbase",
					Notes: fmt.Sprintf("product=%s, received from %s sale", product, base),
				})
			}
		}
	}

	return txns, warnings, nil
}

func parseTimestamp(s string) (time.Time, error) {
	// Strip trailing timezone names (e.g. "UTC") - time.Parse needs explicit layout
	s = strings.TrimSuffix(s, " UTC")
	s = strings.TrimSuffix(s, " GMT")

	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.0000",
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02/01/2006 15:04:05",
		"02/01/2006",
		"01/02/2006",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized format: %s", s)
}

func parseNumber(s string) (float64, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ",", "")
	// Remove currency symbols anywhere in the string (handles -£123, $123, etc.)
	s = strings.ReplaceAll(s, "£", "")
	s = strings.ReplaceAll(s, "$", "")
	s = strings.ReplaceAll(s, "\u20ac", "")
	s = strings.TrimPrefix(s, "\"")
	s = strings.TrimSuffix(s, "\"")
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0, nil
	}
	return strconv.ParseFloat(s, 64)
}

func max(vals ...int) int {
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}
