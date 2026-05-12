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

BRANCH="main"
FORCE=false
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
        *) BRANCH="$arg" ;;
    esac
done

cd "$ASLAM_DIR"

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
