# Memory profiling

Open `/admin` as an administrator. The Memory section shows RSS (Linux), Go heap allocation, goroutines, GC count, database connection counts and the configured model. Refresh to take another measurement. No background sampling or model calls are added.

1. Download a **heap** profile and snapshot JSON after startup has settled. Heap downloads force a garbage collection first; refresh the admin figures afterwards.
2. Use the app normally, or leave it idle to isolate background activity. Record elapsed time and activity.
3. When memory grows, download another heap profile and JSON snapshot before restarting. Use the same running process/build for both.
4. Compare retained allocations with Go's profiler (rename the downloads):

   ```sh
   go tool pprof -top -sample_index=inuse_space -base=before.pprof after.pprof
   ```

Download **allocations** profiles to compare allocation churn using `-sample_index=alloc_space`. Download **goroutines** at both times if the count keeps increasing; `go tool pprof -top goroutines.pprof` groups stacks. Profiles are sampled, so small differences may be noise.

RSS rising alone does not establish a leak. Go can keep freed heap pages for reuse; SQLite's native memory and resident mapped pages are also outside the Go heap. If post-GC retained heap and goroutines stay stable while RSS grows, investigate native allocations and process mappings on the host. These endpoints do not measure SQLite's native allocations separately.

All downloads and `/admin/memory` require an admin session, even when OAuth is not configured or an API key is supplied. No public `/debug/pprof` routes are installed. Profiles contain internal function names and should be treated as operational diagnostics.
