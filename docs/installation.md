# Installation and configuration

## Prerequisites

Use Go 1.26.10 or newer, allowing Go to select a newer toolchain when required by dependencies. [go.mod](../go.mod) is authoritative. A C compiler and CGO are required by the SQLCipher driver. The `sqlcipher` command-line program is useful for database administration; it is separate from the application's Go driver.

## Local setup

```sh
git clone https://github.com/asim/aslam.git
cd aslam
mkdir -p ~/.aslam
chmod 700 ~/.aslam
# Create a key only for a new database; never overwrite an existing key.
test -f ~/.aslam/.key || (umask 077; openssl rand -base64 32 > ~/.aslam/.key)
cp .env.example .env
chmod 600 .env
```

Edit `.env`, then build and start:

```sh
go build -o aslam .
./aslam
```

Open http://localhost:8000. Reference browsing does not need an Anthropic key; model responses do. Initial source imports may take time; follow the startup logs.

The app reads `.env` from its working directory. Existing process environment variables take precedence. It accepts an optional `export` prefix, surrounding quotes and whole-line comments; put comments on their own lines.

## Configuration

| Setting | Purpose |
| --- | --- |
| `ASLAM_KEY` | Database encryption key; otherwise read from `~/.aslam/.key` |
| `ASLAM_DB` | Database path; defaults to `~/.aslam/aslam.db` |
| `PORT` | HTTP port; defaults to 8000 |
| `ANTHROPIC_API_KEY` | Enables model responses |
| `ANTHROPIC_MODEL` | Model override; current code defaults to `claude-sonnet-5` |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google OAuth configuration |
| `GOOGLE_REDIRECT_URI` | OAuth callback; defaults to `http://localhost:8000/auth/callback` |
| `ADMIN_EMAILS` | Comma-separated initial administrators, seeded when the users table is empty |
| `BASE_URL` | Public origin for emailed links |
| `ALLOW_PASSWORD_SIGNUP` | Controls new password signup requests; also requires a working sender |
| `ASLAM_ALLOWED_HOSTS` | Allowed hostnames/IPs; see [request limits](request-limits.md) |
| `BRAVE_API_KEY` | Optional web search integration |
| `MODEL_ENABLED` | Set to `false` to disable model calls after restart |
| `LATITUDE`, `LONGITUDE`, `TIMEZONE` | Default prayer location and timezone |

See [operations](operations.md) for `SMTP_*`, `GMAIL_*`, inbound-email authentication and model limits. For application integrations, use [account API keys](api.md), not the removed legacy `API_KEY` or `DEV_TOKEN` bypass settings.

## Authentication and public hosting

Configure Google OAuth or verified email/password accounts and an initial administrator before exposing the service. Account routes always require a verified session; leaving OAuth unset does not disable authentication.

Email/password registration requires a configured sender, address verification and admin approval. `ALLOW_PASSWORD_SIGNUP=false` closes new requests. It does not delete accounts or stop approval of already pending requests.

For production, use HTTPS and a reverse proxy with the backend port private. The existing cookie/domain and canonical redirect handling is tailored to `aslam.org`; adapting to a different domain requires reviewing `internal/server/auth.go`, not just changing the callback URL. Configure allowed hosts and trusted proxy headers as described in [request limits](request-limits.md).

See [operations](operations.md) for systemd deployment and backups.
