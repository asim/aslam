package main

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"strings"
)

// krakenAssets maps Kraken's internal asset codes to standard symbols.
var krakenAssets = map[string]string{
	"XXBT": "BTC", "XBT": "BTC",
	"XETH": "ETH", "XLTC": "LTC",
	"XXRP": "XRP", "XXLM": "XLM",
	"XXMR": "XMR", "XZEC": "ZEC",
	"XETC": "ETC", "XREP": "REP",
	"XMLN": "MLN", "XXDG": "DOGE",
	"XDAO": "DAO", "XICN": "ICN",
	"ZGBP": "GBP", "ZUSD": "USD",
	"ZEUR": "EUR", "ZJPY": "JPY",
	"ZCAD": "CAD", "ZAUD": "AUD",
}

func normalizeAsset(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	if mapped, ok := krakenAssets[s]; ok {
		return mapped
	}
	return s
}

// parseKrakenPair splits a Kraken trading pair into base and quote assets.
func parseKrakenPair(pair string) (base, quote string) {
	pair = strings.TrimSpace(strings.ToUpper(pair))

	// Try known quote suffixes, longest first to avoid partial matches
	quoteSuffixes := []struct{ suffix, symbol string }{
		{"ZGBP", "GBP"}, {"ZUSD", "USD"}, {"ZEUR", "EUR"},
		{"ZJPY", "JPY"}, {"ZCAD", "CAD"}, {"ZAUD", "AUD"},
		{"XXBT", "BTC"}, {"XBT", "BTC"},
		{"GBP", "GBP"}, {"USD", "USD"}, {"EUR", "EUR"},
		{"JPY", "JPY"}, {"CAD", "CAD"}, {"AUD", "AUD"},
	}

	for _, qs := range quoteSuffixes {
		if strings.HasSuffix(pair, qs.suffix) && len(pair) > len(qs.suffix) {
			baseRaw := pair[:len(pair)-len(qs.suffix)]
			return normalizeAsset(baseRaw), qs.symbol
		}
	}

	return pair, ""
}

func parseKraken(filepath string) ([]Transaction, []string, error) {
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

	if len(records) < 2 {
		return nil, nil, fmt.Errorf("CSV file has no data rows")
	}

	// Find header row
	headerIdx := -1
	for i, row := range records {
		if len(row) < 5 {
			continue
		}
		first := strings.TrimSpace(strings.ToLower(strings.Trim(row[0], "\xef\xbb\xbf\"")))
		if first == "txid" {
			headerIdx = i
			break
		}
	}
	if headerIdx == -1 {
		return nil, nil, fmt.Errorf("could not find header row (expected txid column)")
	}

	// Map columns
	cols := map[string]int{}
	for i, name := range records[headerIdx] {
		key := strings.TrimSpace(strings.ToLower(strings.Trim(name, "\"\xef\xbb\xbf")))
		cols[key] = i
	}

	required := []string{"pair", "time", "type", "cost", "fee", "vol"}
	for _, r := range required {
		if _, ok := cols[r]; !ok {
			return nil, nil, fmt.Errorf("missing required column: %q", r)
		}
	}

	pairCol := cols["pair"]
	timeCol := cols["time"]
	typeCol := cols["type"]
	costCol := cols["cost"]
	feeCol := cols["fee"]
	volCol := cols["vol"]

	var txns []Transaction
	var warnings []string

	for i := headerIdx + 1; i < len(records); i++ {
		row := records[i]
		maxCol := max(pairCol, timeCol, typeCol, costCol, feeCol, volCol)
		if len(row) <= maxCol {
			continue
		}

		pair := strings.Trim(strings.TrimSpace(row[pairCol]), "\"")
		base, quote := parseKrakenPair(pair)

		if quote != "GBP" {
			warnings = append(warnings, fmt.Sprintf("Kraken line %d: non-GBP pair %s (%s/%s) - skipped", i+1, pair, base, quote))
			continue
		}

		side := strings.TrimSpace(strings.ToLower(strings.Trim(row[typeCol], "\"")))
		if side != "buy" && side != "sell" {
			continue
		}

		vol, err := parseNumber(row[volCol])
		if err != nil || vol == 0 {
			warnings = append(warnings, fmt.Sprintf("Kraken line %d: invalid volume %q", i+1, row[volCol]))
			continue
		}
		vol = math.Abs(vol)

		cost, _ := parseNumber(row[costCol])
		fee, _ := parseNumber(row[feeCol])
		cost = math.Abs(cost)
		fee = math.Abs(fee)

		ts, err := parseTimestamp(strings.Trim(strings.TrimSpace(row[timeCol]), "\""))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Kraken line %d: bad timestamp %q", i+1, row[timeCol]))
			continue
		}

		var totalGBP float64
		if side == "buy" {
			totalGBP = cost + fee // total outlay including fees
		} else {
			totalGBP = cost - fee // net proceeds after fees
		}

		txns = append(txns, Transaction{
			Date:     ts,
			Type:     side,
			Asset:    base,
			Quantity: vol,
			TotalGBP: totalGBP,
			FeeGBP:   fee,
			Source:   "kraken",
			Notes:    fmt.Sprintf("pair=%s", pair),
		})
	}

	return txns, warnings, nil
}
