package server

import (
	"aslam/db"
	"strings"
	"testing"
)

func TestArabicRootLetters(t *testing.T) {
	for _, tc := range []struct{ arabic, latin string }{{"كتب", "k-t-b"}, {"رحم", "r-ḥ-m"}, {"خرج", "kh-r-j"}, {"زلزل", "z-l-z-l"}} {
		r := displayArabicRoot(db.ArabicRootSummary{Code: "unchanged", Arabic: tc.arabic})
		if r.Pronunciation != tc.latin || strings.Join(r.Letters, "") != tc.arabic || r.Code != "unchanged" {
			t.Fatalf("%s: %+v", tc.arabic, r)
		}
	}
}
