package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"
)

func main() {
	coinbaseFile := flag.String("coinbase", "", "path to Coinbase transaction history CSV")
	krakenFile := flag.String("kraken", "", "path to Kraken trades CSV")
	taxYear := flag.Int("year", time.Now().Year()-1, "tax year (6 Apr YEAR to 5 Apr YEAR+1)")
	flag.Parse()

	if *coinbaseFile == "" && *krakenFile == "" {
		fmt.Fprintln(os.Stderr, "HMRC Capital Gains Tax Report for Crypto Trading")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage: taxreport [--coinbase FILE] [--kraken FILE] [--year YYYY]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  --coinbase  Coinbase transaction history CSV (standard or Pro format)")
		fmt.Fprintln(os.Stderr, "  --kraken    Kraken trades CSV")
		fmt.Fprintln(os.Stderr, "  --year      Tax year, default previous year")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Tax year runs 6 April to 5 April. --year 2024 = 6 Apr 2024 to 5 Apr 2025.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "HMRC share-matching rules applied:")
		fmt.Fprintln(os.Stderr, "  1. Same-day rule")
		fmt.Fprintln(os.Stderr, "  2. Bed & breakfast (30-day) rule")
		fmt.Fprintln(os.Stderr, "  3. Section 104 pool (weighted average)")
		os.Exit(1)
	}

	var allTxns []Transaction
	var warnings []string

	if *coinbaseFile != "" {
		txns, warns, err := parseCoinbase(*coinbaseFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing Coinbase CSV: %v\n", err)
			os.Exit(1)
		}
		allTxns = append(allTxns, txns...)
		warnings = append(warnings, warns...)
		fmt.Fprintf(os.Stderr, "Coinbase: loaded %d transactions\n", len(txns))
	}

	if *krakenFile != "" {
		txns, warns, err := parseKraken(*krakenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing Kraken CSV: %v\n", err)
			os.Exit(1)
		}
		allTxns = append(allTxns, txns...)
		warnings = append(warnings, warns...)
		fmt.Fprintf(os.Stderr, "Kraken: loaded %d transactions\n", len(txns))
	}

	if len(allTxns) == 0 {
		fmt.Fprintln(os.Stderr, "No transactions found in the provided files.")
		os.Exit(1)
	}

	sort.Slice(allTxns, func(i, j int) bool {
		return allTxns[i].Date.Before(allTxns[j].Date)
	})

	yearStart := time.Date(*taxYear, 4, 6, 0, 0, 0, 0, time.UTC)
	yearEnd := time.Date(*taxYear+1, 4, 5, 23, 59, 59, 0, time.UTC)

	disposals := calculateCapitalGains(allTxns, yearStart, yearEnd)
	printReport(disposals, *taxYear, yearStart, yearEnd, allTxns, warnings)
}
