package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func printReport(disposals []DisposalEvent, taxYear int, yearStart, yearEnd time.Time, allTxns []Transaction, warnings []string) {
	fmt.Printf("\nHMRC Capital Gains Report\n")
	fmt.Printf("Tax Year %d/%02d (6 April %d to 5 April %d)\n", taxYear, (taxYear+1)%100, taxYear, taxYear+1)
	fmt.Println(strings.Repeat("=", 70))

	// Transaction summary
	coinbase, kraken := 0, 0
	buys, sells := 0, 0
	assets := map[string]bool{}
	for _, t := range allTxns {
		switch t.Source {
		case "coinbase":
			coinbase++
		case "kraken":
			kraken++
		}
		if t.Type == "buy" {
			buys++
		} else {
			sells++
		}
		assets[t.Asset] = true
	}

	fmt.Printf("\nTransactions loaded: %d (%d buys, %d sells)\n", len(allTxns), buys, sells)
	if coinbase > 0 {
		fmt.Printf("  Coinbase: %d\n", coinbase)
	}
	if kraken > 0 {
		fmt.Printf("  Kraken:   %d\n", kraken)
	}

	assetList := make([]string, 0, len(assets))
	for a := range assets {
		assetList = append(assetList, a)
	}
	sort.Strings(assetList)
	fmt.Printf("  Assets:   %s\n", strings.Join(assetList, ", "))

	// Warnings
	if len(warnings) > 0 {
		fmt.Printf("\nWarnings (%d):\n", len(warnings))
		shown := warnings
		if len(shown) > 20 {
			shown = shown[:20]
		}
		for _, w := range shown {
			fmt.Printf("  * %s\n", w)
		}
		if len(warnings) > 20 {
			fmt.Printf("  ... and %d more warnings\n", len(warnings)-20)
		}
	}

	// Filter disposals within tax year (should already be filtered, but be safe)
	var taxYearDisposals []DisposalEvent
	for _, d := range disposals {
		if !d.Date.Before(yearStart) && !d.Date.After(yearEnd) {
			taxYearDisposals = append(taxYearDisposals, d)
		}
	}

	fmt.Printf("\n%s\n", strings.Repeat("-", 70))
	fmt.Printf("DISPOSALS IN TAX YEAR %d/%02d\n", taxYear, (taxYear+1)%100)
	fmt.Printf("%s\n", strings.Repeat("-", 70))

	if len(taxYearDisposals) == 0 {
		fmt.Println("\nNo taxable disposals in this tax year.")
		return
	}

	// Disposal details
	fmt.Printf("\n%-12s %-6s %14s %12s %12s %12s  %-10s\n",
		"Date", "Asset", "Quantity", "Proceeds", "Cost", "Gain/Loss", "Rule")
	fmt.Println(strings.Repeat("-", 82))

	var totalProceeds, totalCost, totalGains, totalLosses float64
	assetSummary := map[string]*struct{ proceeds, cost, gains, losses float64 }{}

	for _, d := range taxYearDisposals {
		fmt.Printf("%-12s %-6s %14.8f %11.2f %11.2f %11.2f  %-10s\n",
			d.Date.Format("2006-01-02"),
			d.Asset,
			d.Quantity,
			d.Proceeds,
			d.Cost,
			d.Gain,
			d.Rule,
		)

		totalProceeds += d.Proceeds
		totalCost += d.Cost

		s, ok := assetSummary[d.Asset]
		if !ok {
			s = &struct{ proceeds, cost, gains, losses float64 }{}
			assetSummary[d.Asset] = s
		}
		s.proceeds += d.Proceeds
		s.cost += d.Cost
		if d.Gain >= 0 {
			totalGains += d.Gain
			s.gains += d.Gain
		} else {
			totalLosses += d.Gain
			s.losses += d.Gain
		}
	}

	fmt.Println(strings.Repeat("-", 82))

	// Per-asset summary
	if len(assetSummary) > 1 {
		fmt.Println("\nSummary by asset:")
		for _, asset := range assetList {
			s, ok := assetSummary[asset]
			if !ok {
				continue
			}
			net := s.gains + s.losses
			fmt.Printf("  %-6s  proceeds: %10.2f  cost: %10.2f  net: %10.2f\n",
				asset, s.proceeds, s.cost, net)
		}
	}

	// HMRC summary
	net := totalGains + totalLosses

	fmt.Printf("\n%s\n", strings.Repeat("-", 70))
	fmt.Println("SUMMARY FOR SELF ASSESSMENT")
	fmt.Printf("%s\n", strings.Repeat("-", 70))
	fmt.Printf("Number of disposals:    %d\n", len(taxYearDisposals))
	fmt.Printf("Disposal proceeds:      %10.2f\n", totalProceeds)
	fmt.Printf("Allowable costs:        %10.2f\n", totalCost)
	fmt.Printf("Gains in the year:      %10.2f\n", totalGains)
	fmt.Printf("Losses in the year:     %10.2f\n", totalLosses)
	fmt.Printf("Net gain/(loss):        %10.2f\n", net)

	// Annual exempt amount
	exemption := annualExemption(taxYear)
	fmt.Printf("\nAnnual exempt amount:   %10.2f\n", exemption)

	taxable := net - exemption
	if taxable < 0 {
		taxable = 0
	}
	fmt.Printf("Taxable gain:           %10.2f\n", taxable)

	if taxable > 0 {
		fmt.Println("\nNote: Capital Gains Tax rate depends on your income tax band.")
		fmt.Println("Check current rates at gov.uk for the applicable tax year.")
	}

	fmt.Println()
}

func annualExemption(taxYear int) float64 {
	switch {
	case taxYear >= 2024:
		return 3000
	case taxYear == 2023:
		return 6000
	default:
		return 12300
	}
}
