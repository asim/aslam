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

func parseCoinbase(filepath string) ([]Transaction, []string, error) {
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
		return parseCoinbasePro(records, headerIdx, cols)
	}
	return parseCoinbaseStandard(records, headerIdx, cols)
}

func parseCoinbaseStandard(records [][]string, headerIdx int, cols map[string]int) ([]Transaction, []string, error) {
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
	spotCol, hasSpot := cols["spot price at transaction"]
	spotCurrCol, hasSpotCurr := cols["spot price currency"]
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

		switch strings.ToLower(txType) {
		case "buy", "sell", "convert":
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

		// Check currency
		if hasSpotCurr && len(row) > spotCurrCol {
			curr := strings.TrimSpace(strings.ToUpper(row[spotCurrCol]))
			if curr != "GBP" && curr != "" {
				warnings = append(warnings, fmt.Sprintf("Coinbase line %d: non-GBP currency (%s) for %s - skipped", i+1, curr, asset))
				continue
			}
		}

		// Determine GBP values
		var totalGBP, feeGBP float64
		if hasTotal && len(row) > totalCol {
			totalGBP, _ = parseNumber(row[totalCol])
		} else if hasSubtotal && len(row) > subtotalCol {
			totalGBP, _ = parseNumber(row[subtotalCol])
		} else if hasSpot && len(row) > spotCol {
			spot, _ := parseNumber(row[spotCol])
			totalGBP = qty * spot
		}
		totalGBP = math.Abs(totalGBP)

		if hasFee && len(row) > feeCol {
			feeGBP, _ = parseNumber(row[feeCol])
			feeGBP = math.Abs(feeGBP)
		}

		ts, err := parseTimestamp(strings.TrimSpace(row[tsCol]))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Coinbase line %d: bad timestamp %q", i+1, row[tsCol]))
			continue
		}

		var notes string
		if hasNotes && len(row) > notesCol {
			notes = strings.TrimSpace(row[notesCol])
		}

		switch strings.ToLower(txType) {
		case "buy":
			txns = append(txns, Transaction{
				Date: ts, Type: "buy", Asset: asset, Quantity: qty,
				TotalGBP: totalGBP, FeeGBP: feeGBP, Source: "coinbase", Notes: notes,
			})
		case "sell":
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

func parseCoinbasePro(records [][]string, headerIdx int, cols map[string]int) ([]Transaction, []string, error) {
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
		asset := strings.ToUpper(parts[0])
		quoteCurrency := strings.ToUpper(parts[1])

		if hasUnit && len(row) > unitCol {
			quoteCurrency = strings.TrimSpace(strings.ToUpper(row[unitCol]))
		}
		if quoteCurrency != "GBP" {
			warnings = append(warnings, fmt.Sprintf("Coinbase Pro line %d: non-GBP pair %s - skipped", i+1, product))
			continue
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

		txns = append(txns, Transaction{
			Date: ts, Type: side, Asset: asset, Quantity: qty,
			TotalGBP: total, FeeGBP: fee, Source: "coinbase",
		})
	}

	return txns, warnings, nil
}

func parseTimestamp(s string) (time.Time, error) {
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
	s = strings.TrimPrefix(s, "£")
	s = strings.TrimPrefix(s, "$")
	s = strings.TrimPrefix(s, "\u20ac")
	s = strings.TrimPrefix(s, "\"")
	s = strings.TrimSuffix(s, "\"")
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
