package server

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
)

// Pagination is opt-in for HTTP/MCP and enabled by chat. Character offsets are
// Unicode code points, so concatenating pages reconstructs the original field.
func paginateKnowledgeText(item map[string]interface{}, values url.Values) (map[string]interface{}, map[string]interface{}, error) {
	if values.Get("text_limit") == "" && values.Get("text_offset") == "" && values.Get("text_field") == "" {
		return item, nil, nil
	}
	limit := 12000
	offset := 0
	var err error
	if raw := values.Get("text_limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 12000 {
			return nil, nil, fmt.Errorf("text_limit must be 1 to 12000")
		}
	}
	if raw := values.Get("text_offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return nil, nil, fmt.Errorf("invalid text_offset")
		}
	}
	fields := []string{}
	for name, value := range item {
		if _, ok := value.(string); ok && name != "HTML" {
			fields = append(fields, name)
		}
	}
	sort.Strings(fields)
	field := values.Get("text_field")
	if field == "" {
		for _, name := range []string{"Content", "Text", "Answer", "English", "Summary", "VersesJSON"} {
			if _, ok := item[name].(string); ok {
				field = name
				break
			}
		}
	}
	if field == "" {
		return item, nil, nil
	}
	text, ok := item[field].(string)
	if !ok || field == "HTML" {
		return nil, nil, fmt.Errorf("unknown text_field")
	}
	chars := []rune(text)
	if offset > len(chars) {
		return nil, nil, fmt.Errorf("text_offset exceeds passage length")
	}
	end := min(offset+limit, len(chars))
	out := map[string]interface{}{field: string(chars[offset:end])}
	// Keep short metadata, but never duplicate the passage as HTML or another field.
	for _, name := range []string{"Title", "Author", "Translator", "Edition", "SourceURL", "Previous", "Next"} {
		if v, ok := item[name]; ok && name != field {
			out[name] = v
		}
	}
	page := map[string]interface{}{"field": field, "offset": offset, "total": len(chars), "fields": fields, "next": nil}
	if end < len(chars) {
		page["next"] = end
	}
	return out, page, nil
}
