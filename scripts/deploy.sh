#!/bin/bash
# Aslam deploy script
# Pulls latest from GitHub, builds, and restarts the service.
# Run manually or via the aslam-update systemd timer.
#
# Usage:
#   ./deploy.sh                 - check origin/main, deploy if changed
#   ./deploy.sh <branch>        - check origin/<branch>, deploy if changed
#   ./deploy.sh <branch> --force - rebuild & restart even if nothing changed
set -e

ASLAM_DIR="/home/aslam"
LOG_TAG="aslam-deploy"

# Make sure the Go toolchain is on PATH. systemd/root shells often don't have
# /usr/local/go/bin, which is where the standard tarball install lands.
export PATH="/usr/local/go/bin:$HOME/go/bin:/usr/local/bin:$PATH"
if ! command -v go >/dev/null 2>&1; then
    logger -t "$LOG_TAG" "ERROR: go not found on PATH"
    echo "go not found on PATH (looked in /usr/local/go/bin etc.)" >&2
    exit 1
fi

BRANCH="main"
FORCE=false
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
        *) BRANCH="$arg" ;;
    esac
done

cd "$ASLAM_DIR"

# When running as root, git refuses to operate on a directory owned by another
# user unless it's marked safe. This persists in ~/.gitconfig so it's a one-time
# fix, but harmless to repeat.
git config --global --add safe.directory "$ASLAM_DIR" 2>/dev/null || true

git fetch origin "$BRANCH" 2>/dev/null
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "origin/$BRANCH")

if [ "$FORCE" = false ] && [ "$LOCAL" = "$REMOTE" ] && [ -f "$ASLAM_DIR/aslam" ]; then
    logger -t "$LOG_TAG" "Already up to date ($LOCAL)"
    exit 0
fi

logger -t "$LOG_TAG" "Deploying $BRANCH: $LOCAL -> $REMOTE (force=$FORCE)"

git reset --hard "origin/$BRANCH"
go build -buildvcs=false -o "$ASLAM_DIR/aslam" .

# This script typically runs as root (via aslam-update.service) so fix up
# ownership of anything git/go touched, otherwise the aslam user can't build
# or git-fetch next time (git exits 128 -> "error obtaining VCS status").
chown -R aslam:aslam "$ASLAM_DIR"

logger -t "$LOG_TAG" "Build complete, restarting service"
systemctl restart aslam

logger -t "$LOG_TAG" "Deploy complete ($(git rev-parse --short HEAD))"
