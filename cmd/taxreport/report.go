package main

import (
	"fmt"
	"os"
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

	type assetStats struct {
		quantity                       float64
		proceeds, cost, gains, losses  float64
	}

	var totalProceeds, totalCost, totalGains, totalLosses float64
	assetSummary := map[string]*assetStats{}

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
			s = &assetStats{}
			assetSummary[d.Asset] = s
		}
		s.quantity += d.Quantity
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
		fmt.Printf("  %-6s %16s %12s %12s %12s\n", "Asset", "Qty Disposed", "Proceeds", "Cost", "Net")
		fmt.Printf("  %s\n", strings.Repeat("-", 60))
		for _, asset := range assetList {
			s, ok := assetSummary[asset]
			if !ok {
				continue
			}
			net := s.gains + s.losses
			fmt.Printf("  %-6s %16.8f %12.2f %12.2f %12.2f\n",
				asset, s.quantity, s.proceeds, s.cost, net)
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

func exportCSV(filepath string, disposals []DisposalEvent, taxYear int) error {
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Header
	fmt.Fprintf(f, "Tax Year %d/%02d - Capital Gains Disposals\n", taxYear, (taxYear+1)%100)
	fmt.Fprintln(f, "Date,Asset,Quantity,Disposal Proceeds (GBP),Allowable Cost (GBP),Gain/Loss (GBP),Matching Rule")

	var totalProceeds, totalCost, totalGains, totalLosses float64
	for _, d := range disposals {
		fmt.Fprintf(f, "%s,%s,%.8f,%.2f,%.2f,%.2f,%s\n",
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
		if d.Gain >= 0 {
			totalGains += d.Gain
		} else {
			totalLosses += d.Gain
		}
	}

	// Summary rows
	net := totalGains + totalLosses
	exemption := annualExemption(taxYear)
	taxable := net - exemption
	if taxable < 0 {
		taxable = 0
	}

	fmt.Fprintln(f, "")
	fmt.Fprintln(f, "SUMMARY")
	fmt.Fprintf(f, "Number of disposals,,,,%d\n", len(disposals))
	fmt.Fprintf(f, "Total disposal proceeds,,,,%.2f\n", totalProceeds)
	fmt.Fprintf(f, "Total allowable costs,,,,%.2f\n", totalCost)
	fmt.Fprintf(f, "Total gains,,,,%.2f\n", totalGains)
	fmt.Fprintf(f, "Total losses,,,,%.2f\n", totalLosses)
	fmt.Fprintf(f, "Net gain/(loss),,,,%.2f\n", net)
	fmt.Fprintf(f, "Annual exempt amount,,,,%.2f\n", exemption)
	fmt.Fprintf(f, "Taxable gain,,,,%.2f\n", taxable)

	return nil
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
