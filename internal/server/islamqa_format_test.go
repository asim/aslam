package server

import "testing"

func TestIslamQAParagraphs(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"wrapped", "Praise be to Allah.\nFirstly:\n\nThe cross is one \n\tof the symbols.\n\nNext paragraph.", "<p>Praise be to Allah.</p><p>Firstly:</p><p>The cross is one of the symbols.</p><p>Next paragraph.</p>"},
		{"modern", "First paragraph.\nSecond paragraph.", "<p>First paragraph.</p><p>Second paragraph.</p>"},
		{"numbered", "Introduction:\n\n1.\nFirst item with\na continuation.\n2. Second item.", "<p>Introduction:</p><p>1. First item with a continuation.</p><p>2. Second item.</p>"},
		{"escape", "<script>alert(1)</script>\r\n \t\r\nText & more", "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p><p>Text &amp; more</p>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(islamQAParagraphs(tc.input)); got != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}
