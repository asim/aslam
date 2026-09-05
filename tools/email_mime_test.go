package tools

import (
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

func TestBuildEmailMessageRendersMarkdownAlternatives(t *testing.T) {
	source := "# Heading\n\nA **bold** answer with [a link](https://example.com).\n\n" +
		"[logs](https://host/search?q=*error*)\n\nhttps://verify.example/token\n\n" +
		"Inline: `def __init__(self, **kwargs):`\n\n```python\ndef __init__(self, **kwargs):\n    pass\n```\n\n" +
		"- first\n- second\n\n<script>alert('x')</script>"
	message, err := buildEmailMessage(
		"assistant@aslam.org",
		"user@example.com",
		"Re: Test",
		source,
		"<reply@aslam.org>",
		"<original@example.com>",
		"<original@example.com>",
	)
	if err != nil {
		t.Fatalf("buildEmailMessage: %v", err)
	}

	parsed, err := mail.ReadMessage(strings.NewReader(string(message)))
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse Content-Type: %v", err)
	}
	if mediaType != "multipart/alternative" {
		t.Fatalf("Content-Type = %q, want multipart/alternative", mediaType)
	}

	reader := multipart.NewReader(parsed.Body, params["boundary"])
	parts := make(map[string]string)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read MIME part: %v", err)
		}
		data, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("read part body: %v", err)
		}
		partType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			t.Fatalf("parse part Content-Type: %v", err)
		}
		parts[partType] = string(data)
	}

	plain := parts["text/plain"]
	if strings.Contains(plain, "**bold**") || strings.Contains(plain, "# Heading") {
		t.Errorf("plain part still contains formatting markers: %q", plain)
	}
	if !strings.Contains(plain, "Heading") || !strings.Contains(plain, "a link (https://example.com)") {
		t.Errorf("plain part lost readable content: %q", plain)
	}
	if strings.Count(plain, "def __init__(self, **kwargs):") != 2 {
		t.Errorf("plain part altered code tokens: %q", plain)
	}

	html := parts["text/html"]
	for _, want := range []string{
		"<h1>Heading</h1>",
		"<strong>bold</strong>",
		"<a href=\"https://example.com\">a link</a>",
		"<a href=\"https://host/search?q=*error*\">logs</a>",
		"<a href=\"https://verify.example/token\">https://verify.example/token</a>",
		"<code>def __init__(self, **kwargs):</code>",
		"<pre><code>def __init__(self, **kwargs):",
		"<ul><li>first</li><li>second</li></ul>",
		"&lt;script&gt;",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML part missing %q: %q", want, html)
		}
	}
	if strings.Contains(html, "<script>") {
		t.Errorf("HTML part contains unescaped script: %q", html)
	}
}

func TestBuildEmailMessageRemovesHeaderNewlines(t *testing.T) {
	message, err := buildEmailMessage(
		"assistant@aslam.org",
		"user@example.com",
		"Safe\r\nBcc: attacker@example.com",
		"Hello",
		"<reply@aslam.org>",
		"",
		"",
	)
	if err != nil {
		t.Fatalf("buildEmailMessage: %v", err)
	}
	if strings.Contains(string(message), "\r\nBcc:") {
		t.Fatal("subject injected a Bcc header")
	}
}
