package db

import (
	"context"
	"database/sql"
	"errors"
	sqlite "github.com/mutecomm/go-sqlcipher/v4"
	"path/filepath"
	"testing"
	"time"
)

func limitedTestDB(t *testing.T) {
	t.Helper()
	old := DB
	var err error
	DB, err = sql.Open("sqlite3", filepath.Join(t.TempDir(), "test.db")+"?_busy_timeout=1000")
	if err != nil {
		t.Fatal(err)
	}
	DB.SetMaxOpenConns(1)
	t.Cleanup(func() { DB.Close(); DB = old })
}

func TestReaderCancelsWhileWaitingForConnection(t *testing.T) {
	limitedTestDB(t)
	conn, err := DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = GetAllIslamQAContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	conn.Close()
	if err = DB.Ping(); err != nil {
		t.Fatal(err)
	}
	if DB.Stats().InUse != 0 {
		t.Fatal("connection retained")
	}
}

func TestReaderInterruptsExpensiveSQLiteQuery(t *testing.T) {
	limitedTestDB(t)
	// Force real SQLite work before the reader can return its first row.
	_, err := DB.Exec(`CREATE VIEW islamqa AS WITH RECURSIVE n(x) AS
 (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000)
 SELECT sum(x) AS id, 'slug' AS slug, 'category' AS category, 'question' AS question FROM n`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = GetAllIslamQAContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected interrupted query, got %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("query did not stop promptly")
	}
	if DB.Stats().InUse != 0 {
		t.Fatal("query retained connection")
	}
	if err = DB.Ping(); err != nil {
		t.Fatal(err)
	}
}

func TestKnowledgeSearchSkipsUnrequestedCollections(t *testing.T) {
	limitedTestDB(t)
	for _, q := range []string{
		`CREATE TABLE quran(id INTEGER PRIMARY KEY, chapter INTEGER, chapter_name TEXT, verse INTEGER, text TEXT, arabic TEXT, commentary TEXT)`,
		`CREATE VIRTUAL TABLE quran_fts USING fts4(text)`,
		`INSERT INTO quran VALUES(1,1,'Opening',1,'mercy','',''),(2,1,'Opening',2,'mercy','','')`,
		`INSERT INTO quran_fts(docid,text) VALUES(1,'mercy'),(2,'mercy')`,
	} {
		if _, err := DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	conn, err := DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	selects := 0
	err = conn.Raw(func(raw interface{}) error {
		raw.(*sqlite.SQLiteConn).RegisterAuthorizer(func(op int, a, b, c string) int {
			if op == sqlite.SQLITE_SELECT {
				selects++
			}
			return sqlite.SQLITE_OK
		})
		return nil
	})
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SearchQuranContext(context.Background(), "mercy"); err != nil {
		t.Fatal(err)
	}
	baselineSelects := selects
	selects = 0
	results, err := SearchKnowledgeContext(context.Background(), "mercy", "quran", 1)
	if err != nil || len(results) != 1 || results[0]["Kind"] != "quran" {
		t.Fatalf("%v %v", results, err)
	}
	// Compare to one direct collection query, including SQLite's internal FTS SELECTs.
	// Other collections attempt additional SELECTs even when their tables are absent.
	if selects == 0 || selects > baselineSelects {
		t.Fatalf("queried unrequested collections: %d SELECTs", selects)
	}
}

func TestProductionPoolIsBounded(t *testing.T) {
	old := DB
	t.Setenv("ASLAM_KEY", "pool-test-key")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "pool.db"))
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	defer func() { DB.Close(); DB = old }()
	if DB.Stats().MaxOpenConnections != 4 {
		t.Fatal("unbounded pool")
	}
	var held []*sql.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < 4; i++ {
		c, err := DB.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if c, err := DB.Conn(ctx); !errors.Is(err, context.DeadlineExceeded) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("fifth connection: %v", err)
	}
	for _, c := range held {
		c.Close()
	}
	held = nil
	if stats := DB.Stats(); stats.InUse != 0 || stats.Idle > 2 {
		t.Fatalf("pool retained too much: %+v", stats)
	}
}
