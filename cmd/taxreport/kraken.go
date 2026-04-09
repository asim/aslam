package main

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"
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

	quoteSuffixes := []struct{ suffix, symbol string }{
		{"ZGBP", "GBP"}, {"ZUSD", "USD"}, {"ZEUR", "EUR"},
		{"ZJPY", "JPY"}, {"ZCAD", "CAD"}, {"ZAUD", "AUD"},
		{"XXBT", "BTC"}, {"XBT", "BTC"},
		{"USDT", "USDT"}, {"USDC", "USDC"},
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

func parseKraken(filepath string, rates *ExchangeRates) ([]Transaction, []string, error) {
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

	// Detect format: trades (has "pair") vs ledger (has "refid" + "asset")
	if _, hasPair := cols["pair"]; hasPair {
		return parseKrakenTrades(records, headerIdx, cols, rates)
	}
	if _, hasRefid := cols["refid"]; hasRefid {
		if _, hasAsset := cols["asset"]; hasAsset {
			return parseKrakenLedger(records, headerIdx, cols, rates)
		}
	}

	return nil, nil, fmt.Errorf("unrecognized Kraken CSV format (expected trades with 'pair' column or ledger with 'refid'/'asset' columns)")
}

// parseKrakenLedger handles the Kraken Ledger export format.
// Trade entries come in pairs sharing a refid: one negative (sold) and one positive (received).
func parseKrakenLedger(records [][]string, headerIdx int, cols map[string]int, rates *ExchangeRates) ([]Transaction, []string, error) {
	required := []string{"refid", "time", "type", "asset", "amount", "fee"}
	for _, r := range required {
		if _, ok := cols[r]; !ok {
			return nil, nil, fmt.Errorf("missing required column: %q", r)
		}
	}

	refidCol := cols["refid"]
	timeCol := cols["time"]
	typeCol := cols["type"]
	assetCol := cols["asset"]
	amountCol := cols["amount"]
	feeCol := cols["fee"]

	type ledgerEntry struct {
		ts      time.Time
		asset   string
		amount  float64
		fee     float64
		lineNum int
	}

	// Group trade entries by refid, preserving order
	tradeGroups := map[string][]ledgerEntry{}
	var refidOrder []string

	var warnings []string

	for i := headerIdx + 1; i < len(records); i++ {
		row := records[i]
		maxCol := max(refidCol, timeCol, typeCol, assetCol, amountCol, feeCol)
		if len(row) <= maxCol {
			continue
		}

		txType := strings.TrimSpace(strings.Trim(row[typeCol], "\""))
		if txType != "trade" {
			// Skip deposits, withdrawals, staking, etc.
			if txType == "deposit" || txType == "withdrawal" {
				asset := normalizeAsset(strings.Trim(row[assetCol], "\""))
				amount, _ := parseNumber(row[amountCol])
				if !isFiat(asset) && amount > 0 {
					warnings = append(warnings, fmt.Sprintf(
						"Kraken line %d: %s of %.8f %s - cost basis not tracked (use source exchange data)",
						i+1, txType, amount, asset))
				}
			}
			continue
		}

		refid := strings.TrimSpace(strings.Trim(row[refidCol], "\""))
		if refid == "" {
			continue
		}

		ts, err := parseTimestamp(strings.Trim(strings.TrimSpace(row[timeCol]), "\""))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Kraken line %d: bad timestamp", i+1))
			continue
		}

		asset := normalizeAsset(strings.Trim(row[assetCol], "\""))
		amount, _ := parseNumber(row[amountCol])
		fee, _ := parseNumber(row[feeCol])
		fee = math.Abs(fee)

		if _, seen := tradeGroups[refid]; !seen {
			refidOrder = append(refidOrder, refid)
		}
		tradeGroups[refid] = append(tradeGroups[refid], ledgerEntry{
			ts: ts, asset: asset, amount: amount, fee: fee, lineNum: i + 1,
		})
	}

	var txns []Transaction

	for _, refid := range refidOrder {
		entries := tradeGroups[refid]
		if len(entries) != 2 {
			warnings = append(warnings, fmt.Sprintf(
				"Kraken: trade refid %s has %d entries (expected 2) - skipped", refid, len(entries)))
			continue
		}

		// Identify sell side (negative amount) and buy side (positive amount)
		var sellSide, buySide *ledgerEntry
		for idx := range entries {
			if entries[idx].amount < 0 {
				sellSide = &entries[idx]
			} else {
				buySide = &entries[idx]
			}
		}
		if sellSide == nil || buySide == nil {
			warnings = append(warnings, fmt.Sprintf(
				"Kraken: trade refid %s has no clear sell/buy sides - skipped", refid))
			continue
		}

		sellAsset := sellSide.asset
		sellQty := math.Abs(sellSide.amount)
		buyAsset := buySide.asset
		buyGross := buySide.amount
		buyFee := buySide.fee
		buyNet := buyGross - buyFee
		ts := sellSide.ts

		// Determine GBP value
		var gbpValue float64
		var feeGBP float64
		var ok bool

		if buyAsset == "GBP" {
			// Sold crypto for GBP
			gbpValue = buyNet
			feeGBP = buyFee
			ok = true
		} else if sellAsset == "GBP" {
			// Bought crypto with GBP
			gbpValue = sellQty
			// Fee is in the buy asset; estimate GBP equivalent
			if buyGross > 0 {
				feeGBP = buyFee * (sellQty / buyGross)
			}
			ok = true
		} else if rates.HasRate(buyAsset) {
			// Received side is convertible (e.g., USDT, USDC)
			gbpValue, _ = rates.ToGBP(buyNet, buyAsset, ts)
			feeGBP, _ = rates.ToGBP(buyFee, buyAsset, ts)
			ok = true
		} else if rates.HasRate(sellAsset) {
			// Sell side is convertible
			gbpValue, _ = rates.ToGBP(sellQty, sellAsset, ts)
			feeGBP = 0
			ok = true
		}

		if !ok {
			warnings = append(warnings, fmt.Sprintf(
				"Kraken line %d: no GBP rate for %s/%s trade (refid %s) - skipped. Use --usd-gbp or --rates",
				sellSide.lineNum, sellAsset, buyAsset, refid))
			continue
		}

		// Create disposal of the sold asset
		if !isFiat(sellAsset) {
			txns = append(txns, Transaction{
				Date: ts, Type: "sell", Asset: sellAsset, Quantity: sellQty,
				TotalGBP: gbpValue, FeeGBP: feeGBP, Source: "kraken",
				Notes: fmt.Sprintf("refid=%s, sold for %s", refid, buyAsset),
			})
		}

		// Create acquisition of the received asset
		if !isFiat(buyAsset) {
			txns = append(txns, Transaction{
				Date: ts, Type: "buy", Asset: buyAsset, Quantity: buyNet,
				TotalGBP: gbpValue, FeeGBP: 0, Source: "kraken",
				Notes: fmt.Sprintf("refid=%s, bought with %s", refid, sellAsset),
			})
		}
	}

	// Sort by date
	sort.Slice(txns, func(i, j int) bool {
		return txns[i].Date.Before(txns[j].Date)
	})

	return txns, warnings, nil
}

// parseKrakenTrades handles the Kraken Trades export format.
func parseKrakenTrades(records [][]string, headerIdx int, cols map[string]int, rates *ExchangeRates) ([]Transaction, []string, error) {
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

		if quote == "" {
			warnings = append(warnings, fmt.Sprintf("Kraken line %d: could not parse pair %q - skipped", i+1, pair))
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

		if quote == "GBP" {
			var totalGBP float64
			if side == "buy" {
				totalGBP = cost + fee
			} else {
				totalGBP = cost - fee
			}
			txns = append(txns, Transaction{
				Date: ts, Type: side, Asset: base, Quantity: vol,
				TotalGBP: totalGBP, FeeGBP: fee, Source: "kraken",
				Notes: fmt.Sprintf("pair=%s", pair),
			})
			continue
		}

		if !rates.HasRate(quote) {
			warnings = append(warnings, fmt.Sprintf(
				"Kraken line %d: no exchange rate for %s (pair %s) - skipped. Use --usd-gbp or --rates",
				i+1, quote, pair))
			continue
		}

		if side == "buy" {
			gbpTotal, _ := rates.ToGBP(cost+fee, quote, ts)
			feeGBP, _ := rates.ToGBP(fee, quote, ts)

			txns = append(txns, Transaction{
				Date: ts, Type: "buy", Asset: base, Quantity: vol,
				TotalGBP: gbpTotal, FeeGBP: feeGBP, Source: "kraken",
				Notes: fmt.Sprintf("pair=%s, cost=%.4f %s", pair, cost+fee, quote),
			})
			if !isFiat(quote) {
				txns = append(txns, Transaction{
					Date: ts, Type: "sell", Asset: quote, Quantity: cost + fee,
					TotalGBP: gbpTotal, FeeGBP: 0, Source: "kraken",
					Notes: fmt.Sprintf("pair=%s, exchanged for %s", pair, base),
				})
			}
		} else {
			gbpNet, _ := rates.ToGBP(cost-fee, quote, ts)
			feeGBP, _ := rates.ToGBP(fee, quote, ts)

			txns = append(txns, Transaction{
				Date: ts, Type: "sell", Asset: base, Quantity: vol,
				TotalGBP: gbpNet, FeeGBP: feeGBP, Source: "kraken",
				Notes: fmt.Sprintf("pair=%s, received=%.4f %s", pair, cost-fee, quote),
			})
			if !isFiat(quote) {
				txns = append(txns, Transaction{
					Date: ts, Type: "buy", Asset: quote, Quantity: cost - fee,
					TotalGBP: gbpNet, FeeGBP: 0, Source: "kraken",
					Notes: fmt.Sprintf("pair=%s, received from %s sale", pair, base),
				})
			}
		}
	}

	return txns, warnings, nil
}
