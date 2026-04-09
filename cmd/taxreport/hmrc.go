package main

import (
	"math"
	"sort"
	"strings"
	"time"
)

// calculateCapitalGains applies HMRC share-matching rules to compute taxable disposals.
//
// All transactions are needed to build the Section 104 pool history, but only
// disposals within [yearStart, yearEnd] are returned in the result.
//
// HMRC matching order for each disposal:
//  1. Same-day rule: match with acquisitions on the same calendar day
//  2. Bed & breakfast (30-day) rule: match with acquisitions in the 30 days AFTER disposal
//  3. Section 104 pool: match against the weighted-average pool of remaining acquisitions
func calculateCapitalGains(allTxns []Transaction, yearStart, yearEnd time.Time) []DisposalEvent {
	byAsset := map[string][]Transaction{}
	for _, t := range allTxns {
		byAsset[t.Asset] = append(byAsset[t.Asset], t)
	}

	var disposals []DisposalEvent
	for _, txns := range byAsset {
		disposals = append(disposals, processAsset(txns, yearStart, yearEnd)...)
	}

	sort.Slice(disposals, func(i, j int) bool {
		return disposals[i].Date.Before(disposals[j].Date)
	})
	return disposals
}

type acquisition struct {
	date      time.Time
	totalQty  float64
	totalCost float64
	remaining float64
}

type disposal struct {
	date        time.Time
	totalQty    float64
	totalProc   float64
	remaining   float64
	matchedCost float64
	rules       []string
}

func processAsset(txns []Transaction, yearStart, yearEnd time.Time) []DisposalEvent {
	if len(txns) == 0 {
		return nil
	}
	asset := txns[0].Asset

	var acqs []*acquisition
	var disps []*disposal

	for _, t := range txns {
		if t.Type == "buy" {
			acqs = append(acqs, &acquisition{
				date: t.Date, totalQty: t.Quantity, totalCost: t.TotalGBP, remaining: t.Quantity,
			})
		} else {
			disps = append(disps, &disposal{
				date: t.Date, totalQty: t.Quantity, totalProc: t.TotalGBP, remaining: t.Quantity,
			})
		}
	}

	// Sort both lists chronologically
	sort.Slice(acqs, func(i, j int) bool { return acqs[i].date.Before(acqs[j].date) })
	sort.Slice(disps, func(i, j int) bool { return disps[i].date.Before(disps[j].date) })

	// Phase 1: Same-day matching
	for _, d := range disps {
		if d.remaining <= 1e-12 {
			continue
		}
		for _, a := range acqs {
			if a.remaining <= 1e-12 {
				continue
			}
			if sameDay(d.date, a.date) {
				matchQty := math.Min(d.remaining, a.remaining)
				costPortion := (matchQty / a.totalQty) * a.totalCost
				d.matchedCost += costPortion
				d.remaining -= matchQty
				a.remaining -= matchQty
				appendRule(&d.rules, "same-day")
				if d.remaining <= 1e-12 {
					break
				}
			}
		}
	}

	// Phase 2: Bed & breakfast (30-day) matching
	// For each disposal, find acquisitions in the 30 calendar days AFTER the disposal.
	// Process disposals in chronological order; match acquisitions earliest first.
	for _, d := range disps {
		if d.remaining <= 1e-12 {
			continue
		}
		windowEnd := d.date.AddDate(0, 0, 30)
		for _, a := range acqs {
			if a.remaining <= 1e-12 {
				continue
			}
			// Must be strictly after disposal day and within 30 days
			if !sameDay(a.date, d.date) && a.date.After(d.date) && !a.date.After(windowEnd) {
				matchQty := math.Min(d.remaining, a.remaining)
				costPortion := (matchQty / a.totalQty) * a.totalCost
				d.matchedCost += costPortion
				d.remaining -= matchQty
				a.remaining -= matchQty
				appendRule(&d.rules, "30-day")
				if d.remaining <= 1e-12 {
					break
				}
			}
		}
	}

	// Phase 3: Section 104 pool
	// Process all unmatched transactions in chronological order.
	// Unmatched acquisitions are added to the pool; unmatched disposals draw from it.
	type poolEvent struct {
		date    time.Time
		isBuy   bool
		qty     float64
		cost    float64
		dispIdx int
	}

	var events []poolEvent
	for _, a := range acqs {
		if a.remaining > 1e-12 {
			costRemaining := (a.remaining / a.totalQty) * a.totalCost
			events = append(events, poolEvent{date: a.date, isBuy: true, qty: a.remaining, cost: costRemaining})
		}
	}
	for i, d := range disps {
		if d.remaining > 1e-12 {
			events = append(events, poolEvent{date: d.date, isBuy: false, qty: d.remaining, dispIdx: i})
		}
	}

	sort.Slice(events, func(i, j int) bool {
		if events[i].date.Equal(events[j].date) {
			return events[i].isBuy // buys before sells on same day
		}
		return events[i].date.Before(events[j].date)
	})

	var poolQty, poolCost float64

	for _, e := range events {
		if e.isBuy {
			poolQty += e.qty
			poolCost += e.cost
		} else {
			if poolQty > 1e-12 && e.qty > 1e-12 {
				matchQty := math.Min(e.qty, poolQty)
				costPortion := (matchQty / poolQty) * poolCost
				disps[e.dispIdx].matchedCost += costPortion
				disps[e.dispIdx].remaining -= matchQty
				appendRule(&disps[e.dispIdx].rules, "s104")
				poolQty -= matchQty
				poolCost -= costPortion
			}
		}
	}

	// Build results - only include disposals within the tax year
	var result []DisposalEvent
	for _, d := range disps {
		if d.date.Before(yearStart) || d.date.After(yearEnd) {
			continue
		}
		gain := d.totalProc - d.matchedCost
		rule := "s104"
		if len(d.rules) > 0 {
			rule = strings.Join(d.rules, "+")
		}
		result = append(result, DisposalEvent{
			Date:     d.date,
			Asset:    asset,
			Quantity: d.totalQty,
			Proceeds: d.totalProc,
			Cost:     d.matchedCost,
			Gain:     gain,
			Rule:     rule,
		})
	}
	return result
}

func sameDay(a, b time.Time) bool {
	y1, m1, d1 := a.Date()
	y2, m2, d2 := b.Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}

func appendRule(rules *[]string, rule string) {
	for _, r := range *rules {
		if r == rule {
			return
		}
	}
	*rules = append(*rules, rule)
}
