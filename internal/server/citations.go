package server

import (
	"encoding/json"
	"net/url"
	"strings"
)

type Citation struct{ Title, URL string }

func toolCitations(output string) []Citation {
	var data map[string]interface{}
	if json.Unmarshal([]byte(output), &data) != nil {
		return nil
	}
	var citations []Citation
	add := func(title, path string) {
		u, err := url.Parse(path)
		if err != nil || u.User != nil {
			return
		}
		if u.IsAbs() {
			if u.Scheme != "https" || u.Host != "aslam.org" {
				return
			}
		} else {
			if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
				return
			}
			u.Scheme = "https"
			u.Host = "aslam.org"
		}
		switch strings.Split(strings.TrimPrefix(u.Path, "/"), "/")[0] {
		case "quran", "hadith", "names", "tafsir", "seerah", "islamqa", "ghazali", "adhkar", "salihin", "arabic", "stories":
		default:
			return
		}
		if title == "" {
			title = u.Path
		}
		citations = append(citations, Citation{title, u.String()})
	}
	if items, ok := data["results"].([]interface{}); ok {
		for _, v := range items {
			m, _ := v.(map[string]interface{})
			title, _ := m["Title"].(string)
			path, _ := m["URL"].(string)
			add(title, path)
		}
	}
	if path, ok := data["url"].(string); ok {
		title, _ := data["source"].(string)
		if resource, ok := data["resource"].(map[string]interface{}); ok {
			if t, ok := resource["Title"].(string); ok && t != "" {
				title = t
			}
		}
		add(title, path)
	}
	return citations
}
func formatSourcesFooter(used []ToolUsage) string {
	seen := map[string]bool{}
	var out strings.Builder
	for _, tool := range used {
		if tool.Failed || tool.Name != "read" {
			continue
		}
		for _, c := range tool.Citations {
			if seen[c.URL] {
				continue
			}
			seen[c.URL] = true
			if out.Len() == 0 {
				out.WriteString("\n\n---\n**Sources:**\n")
			}
			title := strings.NewReplacer("\\", "\\\\", "[", "\\[", "]", "\\]", "\n", " ", "\r", " ").Replace(c.Title)
			out.WriteString("- [" + title + "](" + c.URL + ")\n")
		}
	}
	return out.String()
}
