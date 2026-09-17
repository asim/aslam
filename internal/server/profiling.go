package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	"aslam/db"
)

var processStarted = time.Now()
var profileMu sync.Mutex

type memorySnapshot struct {
	CapturedAt     string
	Uptime         string
	Model          string
	RSS            string
	HeapAllocated  string
	HeapInUse      string
	HeapIdle       string
	HeapReleased   string
	GoMemory       string
	Goroutines     int
	GCCount        uint32
	HeapAllocBytes uint64
	RSSBytes       *uint64
	Database       sql.DBStats
}

func memoryMiB(n uint64) string { return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20)) }

func captureMemory() memorySnapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s := memorySnapshot{
		CapturedAt: time.Now().UTC().Format(time.RFC3339),
		Uptime:     time.Since(processStarted).Round(time.Second).String(),
		Model:      anthropicModel, RSS: "Unavailable",
		HeapAllocated: memoryMiB(m.HeapAlloc), HeapInUse: memoryMiB(m.HeapInuse),
		HeapIdle: memoryMiB(m.HeapIdle), HeapReleased: memoryMiB(m.HeapReleased),
		GoMemory:   memoryMiB(m.Sys - m.HeapReleased),
		Goroutines: runtime.NumGoroutine(), GCCount: m.NumGC, HeapAllocBytes: m.HeapAlloc,
	}
	// Linux RSS includes native SQLite allocations and resident mapped pages.
	if data, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 1 {
			if pages, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				n := pages * uint64(os.Getpagesize())
				s.RSSBytes = &n
				s.RSS = memoryMiB(n)
			}
		}
	}
	if db.DB != nil {
		s.Database = db.DB.Stats()
	}
	return s
}

func registerProfilingRoutes(mux *http.ServeMux) {
	// Do not import net/http/pprof: it registers unprotected default routes.
	mux.HandleFunc("/admin/memory", requireAuth(requireAdmin(handleMemorySnapshot)))
	mux.HandleFunc("/admin/profile", requireAuth(requireAdmin(handleMemoryProfile)))
}

func handleMemorySnapshot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(captureMemory())
}

func handleMemoryProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", 405)
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind != "heap" && kind != "allocs" && kind != "goroutine" {
		http.Error(w, "Choose heap, allocs or goroutine", http.StatusBadRequest)
		return
	}
	if !profileMu.TryLock() {
		http.Error(w, "Another profile is being captured", http.StatusConflict)
		return
	}
	var buf bytes.Buffer
	func() {
		defer profileMu.Unlock()
		// A post-GC heap snapshot distinguishes retained objects from garbage.
		if kind == "heap" {
			runtime.GC()
		}
		if err := pprof.Lookup(kind).WriteTo(&buf, 0); err != nil {
			buf.Reset()
		}
	}()
	if buf.Len() == 0 {
		http.Error(w, "Could not capture profile", 500)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="aslam-%s-%s.pprof"`, kind, time.Now().UTC().Format("20060102T150405Z")))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(buf.Bytes())
}
