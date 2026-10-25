package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type ArabicRoot struct{ Code, Arabic, Lemma, Type string }
type ArabicVocabulary struct {
	Arabic, Transliteration, English, Type string
	Frequency                              int
	ExampleRef                             string `json:"example_ref"`
	Roots                                  []ArabicRoot
}
type ArabicPassageWord struct {
	Arabic, Transliteration, English string
	VocabularyID                     int64
	Roots                            []ArabicRoot
}
type ArabicPassage struct {
	Chapter, Verse         int
	Title, Arabic, English string
	Words                  []ArabicPassageWord
}
type ArabicRootSummary struct {
	Code, Arabic string
	Count        int
}
type ArabicRootWord struct {
	ID                                            int64
	Arabic, Transliteration, English, Lemma, Type string
}

func initArabicLearning() error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS arabic_roots(word_id INTEGER NOT NULL, code TEXT NOT NULL, arabic TEXT NOT NULL, lemma TEXT NOT NULL, type TEXT NOT NULL, PRIMARY KEY(word_id,code,lemma,type))`,
		`CREATE INDEX IF NOT EXISTS arabic_roots_code ON arabic_roots(code,word_id)`,
		`CREATE TABLE IF NOT EXISTS arabic_passages(chapter INTEGER NOT NULL, verse INTEGER NOT NULL, title TEXT NOT NULL, arabic TEXT NOT NULL, english TEXT NOT NULL, word_count INTEGER NOT NULL, words TEXT NOT NULL, PRIMARY KEY(chapter,verse))`,
		`CREATE INDEX IF NOT EXISTS arabic_passages_length ON arabic_passages(word_count,chapter,verse)`,
	} {
		if _, err := DB.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// ImportArabic enriches in place: saved /arabic/{id} URLs must survive upgrades.
// All data and the version marker commit together, or the previous import remains.
func ImportArabic(vocab []ArabicVocabulary, passages []ArabicPassage, version string) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	key := func(a, l, e, ref string) string { return a + "\x00" + l + "\x00" + e + "\x00" + ref }
	ids := map[string]int64{}
	forms := map[string]int64{}
	rows, err := tx.Query(`SELECT id,arabic,COALESCE(transliteration,''),COALESCE(english,''),COALESCE(example_ref,'') FROM arabic ORDER BY id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var a, l, e, ref string
		if err = rows.Scan(&id, &a, &l, &e, &ref); err != nil {
			rows.Close()
			return err
		}
		ids[key(a, l, e, ref)] = id
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM arabic_roots`); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM arabic_passages`); err != nil {
		return err
	}
	insert, err := tx.Prepare(`INSERT INTO arabic(arabic,transliteration,english,frequency,example_ref,type) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer insert.Close()
	rootInsert, err := tx.Prepare(`INSERT OR IGNORE INTO arabic_roots(word_id,code,arabic,lemma,type) VALUES(?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer rootInsert.Close()
	for _, v := range vocab {
		k := key(v.Arabic, v.Transliteration, v.English, v.ExampleRef)
		id := ids[k]
		if id == 0 {
			res, e := insert.Exec(v.Arabic, v.Transliteration, v.English, v.Frequency, v.ExampleRef, v.Type)
			if e != nil {
				return e
			}
			id, err = res.LastInsertId()
			if err != nil {
				return err
			}
			ids[k] = id
		}
		form := v.Arabic + "\x00" + v.Transliteration
		if forms[form] == 0 {
			forms[form] = id
		}
		for _, root := range v.Roots {
			if _, err = rootInsert.Exec(id, root.Code, root.Arabic, root.Lemma, root.Type); err != nil {
				return err
			}
		}
	}
	passageInsert, err := tx.Prepare(`INSERT INTO arabic_passages(chapter,verse,title,arabic,english,word_count,words) VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer passageInsert.Close()
	for _, p := range passages {
		for i := range p.Words {
			p.Words[i].VocabularyID = forms[p.Words[i].Arabic+"\x00"+p.Words[i].Transliteration]
		}
		words, e := json.Marshal(p.Words)
		if e != nil {
			return e
		}
		if _, err = passageInsert.Exec(p.Chapter, p.Verse, p.Title, p.Arabic, p.English, len(p.Words), string(words)); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`INSERT OR REPLACE INTO settings(key,value) VALUES('arabic_version',?)`, version); err != nil {
		return err
	}
	return tx.Commit()
}
func ArabicRootsContext(ctx context.Context, q string, offset int) ([]ArabicRootSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	q = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(q), "-", ""), " ", "")
	rows, err := DB.QueryContext(ctx, `SELECT code,arabic,COUNT(DISTINCT word_id) FROM arabic_roots WHERE (?='' OR code=? OR arabic=?) GROUP BY code,arabic ORDER BY COUNT(DISTINCT word_id) DESC,code LIMIT 51 OFFSET ?`, q, q, q, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ArabicRootSummary
	for rows.Next() {
		var r ArabicRootSummary
		if err = rows.Scan(&r.Code, &r.Arabic, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func ArabicWordRootsContext(ctx context.Context, id int64) ([]ArabicRoot, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := DB.QueryContext(ctx, `SELECT code,arabic,lemma,type FROM arabic_roots WHERE word_id=? ORDER BY code,lemma,type`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ArabicRoot
	for rows.Next() {
		var r ArabicRoot
		if err = rows.Scan(&r.Code, &r.Arabic, &r.Lemma, &r.Type); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func ArabicRootWordsContext(ctx context.Context, code string, offset int) ([]ArabicRootWord, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := DB.QueryContext(ctx, `SELECT a.id,a.arabic,COALESCE(a.transliteration,''),COALESCE(a.english,''),r.lemma,r.type FROM arabic_roots r JOIN arabic a ON a.id=r.word_id WHERE r.code=? ORDER BY a.frequency DESC,a.id,r.lemma,r.type LIMIT 51 OFFSET ?`, code, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ArabicRootWord
	for rows.Next() {
		var r ArabicRootWord
		if err = rows.Scan(&r.ID, &r.Arabic, &r.Transliteration, &r.English, &r.Lemma, &r.Type); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func ArabicPassagesContext(ctx context.Context, min, max, offset int) ([]ArabicPassage, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := DB.QueryContext(ctx, `SELECT chapter,verse,title,arabic,english FROM arabic_passages WHERE word_count BETWEEN ? AND ? ORDER BY word_count,chapter,verse LIMIT 51 OFFSET ?`, min, max, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ArabicPassage
	for rows.Next() {
		var p ArabicPassage
		if err = rows.Scan(&p.Chapter, &p.Verse, &p.Title, &p.Arabic, &p.English); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func ArabicPassageContext(ctx context.Context, ch, v int) (*ArabicPassage, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	var p ArabicPassage
	var words string
	err := DB.QueryRowContext(ctx, `SELECT chapter,verse,title,arabic,english,words FROM arabic_passages WHERE chapter=? AND verse=?`, ch, v).Scan(&p.Chapter, &p.Verse, &p.Title, &p.Arabic, &p.English, &words)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(words), &p.Words); err != nil {
		return nil, fmt.Errorf("passage words: %w", err)
	}
	return &p, nil
}
