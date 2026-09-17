# Request and database limits

Aslam rejects excess work rather than queueing another unbounded set of handlers:

- 8 concurrent public reader/resource requests, with a shared sublimit of 2 searches (including Arabic search).
- A separate 16-request pool for other routes, so public crawling does not consume every admin/chat slot. This is not a dedicated admin reservation against traffic to other routes.
- Excess requests receive HTTP 503 and `Retry-After: 5` immediately.
- 4 SQLite connections maximum, 2 idle maximum, idle connections retired after one minute. SQLite's busy timeout is explicitly 1 second per connection; journal mode is unchanged.
- Reader/search queries use the request context and a 5-second database deadline, including waiting for a pooled connection. General search shares one deadline across its collections. SQLite cancellation while waiting for a native lock may take up to the busy timeout to be observed.
- Search text is limited to 1,000 bytes. Knowledge search filters collections before querying and passes the remaining result limit into SQL (still at most 10 per collection).
- HTTP headers have a 5-second timeout and 32 KiB cap; request reads have a 15-second timeout and bodies a 1 MiB cap. Idle connections expire after 30 seconds.
- Ordinary requests get a 15-second context and socket write deadline. Chat sends get 5 minutes, retain streaming, and propagate cancellation into model HTTP requests. An already-running tool still uses its own I/O timeout; cancellation is checked before starting another tool. Contexts do not forcibly kill arbitrary Go code.

Unknown Host headers receive HTTP 421 before authentication, database access, or request admission. Defaults are `aslam.org`, `www.aslam.org`, `localhost`, `127.0.0.1` and `::1`. For another deployment set `ASLAM_ALLOWED_HOSTS` to a comma-separated list of hostnames/IPs (without ports); this replaces the defaults. The proxy must preserve the original Host. This check is routing protection, not authentication: a client can deliberately send an allowed Host.

These bounds address overload risk; they do not establish the cause of the observed 1.1 GiB RSS incident. `/admin` memory snapshots continue to report connection counts and pool waits. Compare RSS, live Go heap and database connections during normal traffic and a burst.

## nginx

The logs showing `host: beal-holdings.co.uk` and `server: aslam.org` mean nginx sent an unrelated host's requests to Aslam. This is consistent with Aslam being the default virtual host. It does not establish who configured the domain or whether the traffic is malicious. `recv() failed ... Connection reset by peer` means the upstream connection reset; check restart/OOM events at the same timestamp rather than increasing timeouts blindly.

For an immediate guard, add this inside **each existing Aslam HTTP/HTTPS `server` block**, without altering certificate configuration:

```nginx
if ($host !~* ^(www\.)?aslam\.org$) { return 444; }
```

Then validate and reload:

```sh
sudo nginx -t && sudo systemctl reload nginx
```

[`scripts/nginx/aslam.conf.example`](../scripts/nginx/aslam.conf.example) provides default HTTP/HTTPS rejection, preserved Host forwarding, per-IP request/connection limits, finite proxy timeouts and unbuffered chat streaming. It is an example, not an automatic installer. Merge it into the current configuration, preserving other sites, certificate paths and certificate-renewal locations; do not create duplicate default servers. TLS handshake rejection requires nginx 1.19.4 or later. If there is a CDN/proxy in front, configure real client addresses only from its trusted address ranges before applying per-IP limits. Never trust arbitrary forwarded IP headers.

Check both allowed and foreign Host headers after reload, including a valid TLS SNI with a foreign Host. For example, on the server:

```sh
curl -I --resolve aslam.org:443:127.0.0.1 https://aslam.org/
curl -I --resolve aslam.org:443:127.0.0.1 -H 'Host: beal-holdings.co.uk' https://aslam.org/hadith/1084
curl -I -H 'Host: beal-holdings.co.uk' http://127.0.0.1/hadith/1084
```

Valid requests should reach the application; rejected requests should get an empty reply (nginx 444) and not reach the application. Keep port 8000 inaccessible from the public network. Unknown-host rejection does not stop clients sending `Host: aslam.org`; admission and query limits remain necessary.

References: [nginx request routing](https://nginx.org/en/docs/http/request_processing.html), [request limiting](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html), [TLS handshake rejection](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_reject_handshake).
