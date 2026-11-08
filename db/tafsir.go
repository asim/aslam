package db

import (
	"archive/zip"
	"aslam/data"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	stdhtml "html"
	"io"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

const TafsirEdition = "ibn-kathir"
const TafsirSource = "Tafsir Ibn Kathir (English) — QUL / Tarteel"
const TafsirSourceURL = "https://qul.tarteel.ai/resources/tafsir/35"

func initTafsir() error {
	_, err := DB.Exec(`CREATE TABLE IF NOT EXISTS tafsir_passages(id INTEGER PRIMARY KEY,edition TEXT NOT NULL,ref TEXT NOT NULL,chapter INTEGER NOT NULL,verse INTEGER NOT NULL,html TEXT NOT NULL,text TEXT NOT NULL,UNIQUE(edition,ref));
 CREATE TABLE IF NOT EXISTS tafsir_ayahs(edition TEXT NOT NULL,chapter INTEGER NOT NULL,verse INTEGER NOT NULL,ref TEXT NOT NULL,PRIMARY KEY(edition,chapter,verse));
 CREATE INDEX IF NOT EXISTS tafsir_group ON tafsir_ayahs(edition,ref,chapter,verse);
 CREATE INDEX IF NOT EXISTS tafsir_order ON tafsir_passages(edition,chapter,verse);
 CREATE VIRTUAL TABLE IF NOT EXISTS tafsir_fts USING fts4(text,content='tafsir_passages');
 CREATE TRIGGER IF NOT EXISTS tafsir_ai AFTER INSERT ON tafsir_passages BEGIN INSERT INTO tafsir_fts(docid,text) VALUES(new.id,new.text); END;
 CREATE TRIGGER IF NOT EXISTS tafsir_ad BEFORE DELETE ON tafsir_passages BEGIN DELETE FROM tafsir_fts WHERE docid=old.id; END;`)
	return err
}

// SanitizeTafsir retains formatting and language direction but never scripts,
// images, links, styles or source-supplied attributes. Plain text is indexed.
func SanitizeTafsir(source string) (string, string, error) {
	root, err := html.Parse(strings.NewReader(source))
	if err != nil {
		return "", "", err
	}
	var markup, plain strings.Builder
	allowed := map[string]bool{"p": true, "div": true, "span": true, "h2": true, "h3": true, "h4": true, "b": true, "strong": true, "i": true, "em": true, "br": true, "ul": true, "ol": true, "li": true, "blockquote": true, "sup": true, "sub": true}
	blocks := map[string]bool{"p": true, "div": true, "h2": true, "h3": true, "h4": true, "li": true, "blockquote": true, "br": true}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			markup.WriteString(stdhtml.EscapeString(n.Data))
			plain.WriteString(n.Data)
			return
		}
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "iframe" || n.Data == "object" || n.Data == "svg") {
			return
		}
		ok := n.Type == html.ElementNode && allowed[n.Data]
		if blocks[n.Data] {
			plain.WriteString("\n\n")
		}
		if ok {
			markup.WriteString("<" + n.Data)
			for _, a := range n.Attr {
				if a.Key == "lang" && (a.Val == "ar" || a.Val == "en") {
					markup.WriteString(` lang="` + a.Val + `"`)
					if a.Val == "ar" {
						markup.WriteString(` dir="rtl"`)
					}
				}
			}
			markup.WriteString(">")
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
		if ok && n.Data != "br" {
			markup.WriteString("</" + n.Data + ">")
		}
		if blocks[n.Data] {
			plain.WriteString("\n\n")
		}
	}
	walk(root)
	paragraphs := []string{}
	for _, p := range strings.Split(plain.String(), "\n") {
		p = strings.TrimSpace(p)
		if p != "" {
			paragraphs = append(paragraphs, p)
		}
	}
	return markup.String(), strings.Join(paragraphs, "\n\n"), nil
}

// ImportTafsir streams one passage at a time and commits only after verifying
// every verse and pointer. A failed import leaves the previous edition intact.
func ImportTafsir(archive []byte) error {
	version := fmt.Sprintf("v1-%x", sha256.Sum256(archive))
	if GetSetting("tafsir_version") == version {
		return nil
	}
	var metadata struct {
		Chapters []struct {
			ID    int `json:"id"`
			Count int `json:"verses_count"`
		} `json:"chapters"`
	}
	if err := json.Unmarshal(data.QuranChapters, &metadata); err != nil {
		return err
	}
	valid := map[string]bool{}
	for _, ch := range metadata.Chapters {
		for v := 1; v <= ch.Count; v++ {
			valid[fmt.Sprintf("%d:%d", ch.ID, v)] = true
		}
	}
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return err
	}
	if len(z.File) != 1 || !strings.HasSuffix(z.File[0].Name, ".json") || z.File[0].UncompressedSize64 > 64<<20 {
		return fmt.Errorf("invalid tafsir archive")
	}
	reader, err := z.File[0].Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"tafsir_ayahs", "tafsir_passages"} {
		if _, err = tx.Exec("DELETE FROM "+table+" WHERE edition=?", TafsirEdition); err != nil {
			return err
		}
	}
	dec := json.NewDecoder(io.LimitReader(reader, 64<<20))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("expected tafsir object")
	}
	targets := map[string]string{}
	groups := map[string][]string{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok || !valid[key] {
			return fmt.Errorf("invalid ayah key %v", keyToken)
		}
		if _, ok := targets[key]; ok {
			return fmt.Errorf("duplicate ayah %s", key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		if len(raw) > 0 && raw[0] == '"' {
			var target string
			if err := json.Unmarshal(raw, &target); err != nil {
				return err
			}
			targets[key] = target
			continue
		}
		var passage struct {
			Text  string   `json:"text"`
			Ayahs []string `json:"ayah_keys"`
		}
		if err := json.Unmarshal(raw, &passage); err != nil {
			return err
		}
		clean, text, err := SanitizeTafsir(passage.Text)
		if err != nil {
			return err
		}
		if strings.TrimSpace(text) == "" {
			return fmt.Errorf("empty passage %s", key)
		}
		ch, v := tafsirRef(key)
		if _, err := tx.Exec("INSERT INTO tafsir_passages(edition,ref,chapter,verse,html,text) VALUES(?,?,?,?,?,?)", TafsirEdition, key, ch, v, clean, text); err != nil {
			return err
		}
		targets[key] = key
		groups[key] = passage.Ayahs
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing tafsir data")
	}
	if len(targets) != len(valid) {
		return fmt.Errorf("incomplete tafsir: %d of %d ayahs", len(targets), len(valid))
	}
	resolved := map[string]string{}
	for key := range targets {
		ref := key
		seen := map[string]bool{}
		for {
			target, ok := targets[ref]
			if !ok || seen[ref] {
				return fmt.Errorf("invalid pointer from %s", key)
			}
			seen[ref] = true
			if target == ref {
				if _, ok := groups[ref]; !ok {
					return fmt.Errorf("pointer has no passage: %s", ref)
				}
				break
			}
			ref = target
		}
		resolved[key] = ref
	}
	for ref, ayahs := range groups {
		for _, key := range ayahs {
			if !valid[key] || resolved[key] != ref {
				return fmt.Errorf("inconsistent group %s / %s", ref, key)
			}
		}
	}
	for key, ref := range resolved {
		ch, v := tafsirRef(key)
		if _, err := tx.Exec("INSERT INTO tafsir_ayahs(edition,chapter,verse,ref) VALUES(?,?,?,?)", TafsirEdition, ch, v, ref); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("INSERT INTO settings(key,value) VALUES('tafsir_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", version); err != nil {
		return err
	}
	return tx.Commit()
}
func tafsirRef(ref string) (int, int) {
	parts := strings.Split(ref, ":")
	if len(parts) != 2 {
		return 0, 0
	}
	ch, _ := strconv.Atoi(parts[0])
	v, _ := strconv.Atoi(parts[1])
	return ch, v
}

type TafsirPassage struct {
	Ref, Title, HTML, Text, URL, Previous, Next string
	Chapter, Verse                              int
	Ayahs                                       []string
	Source, SourceURL                           string
}

func GetTafsir(ctx context.Context, chapter, verse int) (*TafsirPassage, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	p := &TafsirPassage{Source: TafsirSource, SourceURL: TafsirSourceURL}
	err := DB.QueryRowContext(ctx, `SELECT p.ref,p.chapter,p.verse,p.html,p.text FROM tafsir_ayahs a JOIN tafsir_passages p ON p.edition=a.edition AND p.ref=a.ref WHERE a.edition=? AND a.chapter=? AND a.verse=?`, TafsirEdition, chapter, verse).Scan(&p.Ref, &p.Chapter, &p.Verse, &p.HTML, &p.Text)
	if err != nil {
		return nil, err
	}
	rows, err := DB.QueryContext(ctx, "SELECT chapter,verse FROM tafsir_ayahs WHERE edition=? AND ref=? ORDER BY chapter,verse", TafsirEdition, p.Ref)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ch, v int
		if err := rows.Scan(&ch, &v); err != nil {
			rows.Close()
			return nil, err
		}
		p.Ayahs = append(p.Ayahs, fmt.Sprintf("%d:%d", ch, v))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	p.Title = "Tafsir Ibn Kathir — " + p.Ayahs[0]
	if len(p.Ayahs) > 1 {
		p.Title += "–" + p.Ayahs[len(p.Ayahs)-1]
	}
	p.URL = fmt.Sprintf("/tafsir/%s/%d/%d", TafsirEdition, p.Chapter, p.Verse)
	for _, nav := range []struct {
		op, order string
		dest      *string
	}{{"<", "DESC", &p.Previous}, {">", "ASC", &p.Next}} {
		var ch, v int
		err := DB.QueryRowContext(ctx, "SELECT chapter,verse FROM tafsir_passages WHERE edition=? AND (chapter*1000+verse) "+nav.op+" ? ORDER BY chapter "+nav.order+",verse "+nav.order+" LIMIT 1", TafsirEdition, p.Chapter*1000+p.Verse).Scan(&ch, &v)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil {
			*nav.dest = fmt.Sprintf("/tafsir/%s/%d/%d", TafsirEdition, ch, v)
		}
	}
	return p, nil
}
func SearchTafsir(ctx context.Context, q string, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 10
	}
	q = sanitiseFTS(q)
	if q == "" {
		return []map[string]any{}, nil
	}
	return QueryAPI(ctx, `SELECT 'tafsir' AS Kind,'Tafsir Ibn Kathir — '||p.ref AS Title,substr(p.text,1,500) AS Content,'Tafsir Ibn Kathir (English) — QUL / Tarteel' AS Source,'/tafsir/ibn-kathir/'||p.chapter||'/'||p.verse AS URL FROM tafsir_fts f JOIN tafsir_passages p ON p.id=f.docid WHERE tafsir_fts MATCH ? ORDER BY p.chapter,p.verse LIMIT ?`, q, limit)
}
func TafsirChapters(ctx context.Context) ([]map[string]any, error) {
	return QueryAPI(ctx, `SELECT chapter AS Chapter,count(*) AS Passages,min(verse) AS FirstVerse FROM tafsir_passages WHERE edition=? GROUP BY chapter ORDER BY chapter`, TafsirEdition)
}
