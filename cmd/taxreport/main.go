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
	usdGBP := flag.Float64("usd-gbp", 0, "fixed USD to GBP rate (e.g. 0.79) for USDT/USDC trades")
	ratesFile := flag.String("rates", "", "CSV file with daily exchange rates (columns: date,USD,EUR,...)")
	csvOut := flag.String("csv", "", "export disposals to CSV file for accountant")
	flag.Parse()

	if *coinbaseFile == "" && *krakenFile == "" {
		fmt.Fprintln(os.Stderr, "HMRC Capital Gains Tax Report for Crypto Trading")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage: taxreport [--coinbase FILE] [--kraken FILE] [--year YYYY]")
		fmt.Fprintln(os.Stderr, "                 [--usd-gbp RATE] [--rates FILE]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  --coinbase  Coinbase transaction history CSV (standard or Pro format)")
		fmt.Fprintln(os.Stderr, "  --kraken    Kraken trades CSV")
		fmt.Fprintln(os.Stderr, "  --year      Tax year, default previous year")
		fmt.Fprintln(os.Stderr, "  --usd-gbp   Fixed USD/GBP rate for USDT/USDC trades (e.g. 0.79)")
		fmt.Fprintln(os.Stderr, "  --rates     CSV with daily rates (columns: date,USD,EUR,...)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Tax year runs 6 April to 5 April. --year 2024 = 6 Apr 2024 to 5 Apr 2025.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "For non-GBP trades (e.g. BNB/USDT), provide a USD/GBP rate so amounts")
		fmt.Fprintln(os.Stderr, "can be converted. USDT and USDC are treated as USD equivalents.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "HMRC share-matching rules applied:")
		fmt.Fprintln(os.Stderr, "  1. Same-day rule")
		fmt.Fprintln(os.Stderr, "  2. Bed & breakfast (30-day) rule")
		fmt.Fprintln(os.Stderr, "  3. Section 104 pool (weighted average)")
		os.Exit(1)
	}

	rates := NewExchangeRates()

	if *ratesFile != "" {
		if err := rates.LoadCSV(*ratesFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading rates file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Loaded exchange rates from %s\n", *ratesFile)
	}

	if *usdGBP > 0 {
		rates.SetFixedRate("USD", *usdGBP)
		fmt.Fprintf(os.Stderr, "Using fixed USD/GBP rate: %.4f\n", *usdGBP)
	}

	var allTxns []Transaction
	var warnings []string

	if *coinbaseFile != "" {
		txns, warns, err := parseCoinbase(*coinbaseFile, rates)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing Coinbase CSV: %v\n", err)
			os.Exit(1)
		}
		allTxns = append(allTxns, txns...)
		warnings = append(warnings, warns...)
		fmt.Fprintf(os.Stderr, "Coinbase: loaded %d transactions\n", len(txns))
	}

	if *krakenFile != "" {
		txns, warns, err := parseKraken(*krakenFile, rates)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing Kraken CSV: %v\n", err)
			os.Exit(1)
		}
		allTxns = append(allTxns, txns...)
		warnings = append(warnings, warns...)
		fmt.Fprintf(os.Stderr, "Kraken: loaded %d transactions\n", len(txns))
	}

	if len(allTxns) == 0 {
		if len(warnings) > 0 {
			fmt.Fprintf(os.Stderr, "\nWarnings (%d):\n", len(warnings))
			for _, w := range warnings {
				fmt.Fprintf(os.Stderr, "  * %s\n", w)
			}
		}
		fmt.Fprintln(os.Stderr, "\nNo transactions found in the provided files.")
		fmt.Fprintln(os.Stderr, "Hint: for USDT/USDC trades, provide --usd-gbp RATE (e.g. --usd-gbp 0.79)")
		os.Exit(1)
	}

	sort.Slice(allTxns, func(i, j int) bool {
		return allTxns[i].Date.Before(allTxns[j].Date)
	})

	yearStart := time.Date(*taxYear, 4, 6, 0, 0, 0, 0, time.UTC)
	yearEnd := time.Date(*taxYear+1, 4, 5, 23, 59, 59, 0, time.UTC)

	disposals := calculateCapitalGains(allTxns, yearStart, yearEnd)
	printReport(disposals, *taxYear, yearStart, yearEnd, allTxns, warnings)

	if *csvOut != "" {
		if err := exportCSV(*csvOut, disposals, *taxYear); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing CSV: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Exported %d disposals to %s\n", len(disposals), *csvOut)
	}
}
