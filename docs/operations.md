# Operations

## Build and deploy

Templates, styles, browser assets and reference archives are embedded. Rebuild and restart the service after changing them.

The supplied [systemd unit](../scripts/aslam.service) assumes an `aslam` user/group and a checkout and binary at `/home/aslam`. The application reads `/home/aslam/.env`; adapt these paths for a different installation.

```sh
go build -o aslam .
sudo cp scripts/aslam.service /etc/systemd/system/aslam.service
sudo systemctl daemon-reload
sudo systemctl enable --now aslam
```

[deploy.sh](../scripts/deploy.sh) fetches a branch (default `main`), resets the deployment checkout to it, builds and restarts the service. It assumes `/home/aslam` and normally runs with privileges to change ownership and restart systemd. Use a dedicated deployment checkout: it discards local tracked changes.

```sh
sudo /home/aslam/scripts/deploy.sh
sudo journalctl -u aslam -f
sudo journalctl -t aslam-deploy
```

The script can be scheduled by the host's systemd timer or cron. No updater timer/service units are supplied in this repository; installing `aslam.service` alone does not enable auto-updates. Keep deployment scheduling in host configuration.

## Verification email and registration

Outbound mail is independent of the assistant's Gmail inbox. For Google's
IP-authorized Workspace relay, configure the service environment:

```sh
SMTP_HOST=smtp-relay.gmail.com
SMTP_PORT=587
SMTP_FROM=noreply@aslam.org
ALLOW_PASSWORD_SIGNUP=true
```

In Google Admin, authorize this server's public egress IP, allow senders in your
domain, and require TLS. Leave `SMTP_USERNAME` and `SMTP_PASSWORD` unset for
IP authorization. No assistant mailbox or IMAP worker is needed. Restart Aslam
after updating its environment. Registration requires email verification followed by admin approval. Verification
links expire after 24 hours. Verified requests expire after 30 days. Approve or
reject requests in Admin → Email signup requests; approval creates the account
and sends a notification. Existing accounts and Google signup are unchanged.

For a relay requiring authentication, set both `SMTP_USERNAME` and
`SMTP_PASSWORD`. Port 587 uses required STARTTLS; port 465 uses implicit TLS.
Sending has a 30-second deadline. Explicit SMTP settings take precedence over
legacy `GMAIL_USER` / `GMAIL_APP_PASSWORD` sending, which still works when no
`SMTP_*` settings are present. Inbox credentials retain their existing purpose.

`ALLOW_PASSWORD_SIGNUP=false` keeps registration closed even with sending
configured. Missing or incomplete sender configuration also keeps it closed.
Configuring a sender alone otherwise enables verified email signup; keep the
flag false while preparing deployment if you are not ready to open signup.

Email signup includes an expiring, single-use addition question and hidden bot
trap. Attempts are limited to 5 per client IP per hour and 60 total per hour.
These in-memory limits and challenges reset on restart and apply per server
process. The arithmetic question deters basic scripts; admin approval is the
access gate. Unverified and verified pending requests cannot log in or use the
assistant email allowlist.

When using nginx on the same host, set `proxy_set_header X-Real-IP $remote_addr;`
so signup limits use client addresses. Only loopback peers are trusted to supply
this header; nginx must overwrite it, not forward a client-provided value. Keep
Aslam's backend port private. Without this header, local-proxy requests share
the same limit. Admin review forms require a same-origin POST.

`ALLOW_PASSWORD_SIGNUP=false` stops new email requests; existing verification
links and admin approval remain usable. Rejected requests are removed and can
be resubmitted, subject to signup limits. No existing accounts are deleted.

## Inbound assistant email

The optional inbox worker uses `GMAIL_USER` and `GMAIL_APP_PASSWORD`. This is separate from SMTP-only verification mail.

A sender must be a verified account. The receiving server's first trusted `Authentication-Results` header must identify `EMAIL_AUTHSERV_ID` (default `mx.google.com`) and show a DMARC pass or an aligned SPF/DKIM pass. See `internal/tools/authresults.go`. Do not enable `EMAIL_ALLOW_UNVERIFIED=true` on a normal deployment: it bypasses sender-domain authentication and leaves the allowlist trusting a forgeable From address.

## AI usage limits

Non-admin accounts can ask five questions per UTC day by default. Admins are exempt
from both daily limits and do not consume the site allowance; their usage is still tracked. Chat, API and queued
email/chat share the allowance. Tool follow-ups are included in the question,
not charged separately; failed initial attempts count. Quotas survive restarts.

Admin shows today's site-wide and per-account question usage and lets admins
change both limits immediately. The optional site-wide limit defaults to zero
(unlimited); a zero per-account limit blocks new questions. MODEL_ENABLED=false
remains an environment emergency stop (restart required).

Tool follow-ups share the original question reservation and continue until an
answer is returned or generation times out or fails. Accepted web questions
continue after a browser disconnect and save their answer for recovery, within
the original five-minute server deadline. They do not consume extra
questions or have a fixed turn limit. Each provider call allows at most 64 KiB of
serialized input and 2,048 output tokens. Requests pack recent context into that
budget; longer source texts are paginated. Output-limit continuations share the
question reservation and original deadline. Chat input is limited to 8 KiB and two
provider calls may run concurrently per process. These are usage limits, not
currency budgets. Queued budget/size/concurrency denials are not auto-retried.
A retry of a failed initial attempt counts as another question attempt.

All model requests require a verified conversation owner. API keys cannot bypass
ownership or quota checks. Public content reading/search and inbox polling do not
call the model. ANTHROPIC_MODEL selects the model (default claude-sonnet-5).

## Diagnostics and backup

Use [request limits](request-limits.md) for HTTP/SQL deadlines and nginx setup, and [memory profiling](memory-profiling.md) for admin-only diagnostics. Pool wait counts and connection churn are useful when investigating latency; do not increase concurrency or timeouts without measurements.

Back up the encrypted database and preserve its matching encryption key separately and securely. Use a consistent SQLite backup or stop the service before copying database files. Include configuration needed to restore the deployment; never commit backups or credentials.

For a handover, add the trusted administrator, document service-account ownership, and transfer server, domain, repository and secret-management access. Verify that the recipient can restore the database with its key and operate the service. The admin page can record service-account details, but it does not transfer access to external providers.
