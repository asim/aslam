package server

import (
	"aslam/db"
	"context"
	"sort"
	"strings"
	"unicode"
)

func referenceScore(item map[string]interface{}, query string) int {
	title, _ := item["Title"].(string)
	content, _ := item["Content"].(string)
	title = strings.ToLower(title)
	content = strings.ToLower(content)
	score := 0
	for _, term := range strings.FieldsFunc(strings.ToLower(query), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) }) {
		if strings.Contains(title, term) {
			score += 4
		}
		if strings.Contains(content, term) {
			score++
		}
	}
	return score
}
func searchReferenceCollections(ctx context.Context, q, collection string, limit int) ([]map[string]interface{}, error) {
	kinds := []string{collection}
	if collection == "" {
		kinds = nil
		for kind := range knowledgeCollections {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
	}
	groups := [][]map[string]interface{}{}
	for _, kind := range kinds {
		var found []map[string]interface{}
		var err error
		switch kind {
		case "arabic", "roots", "reading", "stories":
			found, err = db.BrowseKnowledge(ctx, kind, "", q, 0, limit)
		default:
			found, err = db.SearchKnowledgeContext(ctx, q, kind, limit)
		}
		if err != nil {
			return nil, err
		}
		for _, item := range found {
			item["Kind"] = kind
			item["Source"] = knowledgeCollections[kind]
		}
		sort.SliceStable(found, func(i, j int) bool { return referenceScore(found[i], q) > referenceScore(found[j], q) })
		if len(found) > 0 {
			groups = append(groups, found)
		}
	}
	// Rank each round across sources, so one large collection cannot exhaust the
	// limit before a later collection is even searched.
	results := []map[string]interface{}{}
	for round := 0; len(results) < limit; round++ {
		candidates := []map[string]interface{}{}
		for _, group := range groups {
			if round < len(group) {
				candidates = append(candidates, group[round])
			}
		}
		if len(candidates) == 0 {
			break
		}
		sort.SliceStable(candidates, func(i, j int) bool { return referenceScore(candidates[i], q) > referenceScore(candidates[j], q) })
		for _, item := range candidates {
			results = append(results, item)
			if len(results) == limit {
				break
			}
		}
	}
	return results, nil
}
