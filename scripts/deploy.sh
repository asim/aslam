#!/bin/bash
# Aslam deploy script
# Pulls latest from GitHub, builds, and restarts the service.
# Run manually or via the aslam-update systemd timer.
set -e

ASLAM_DIR="/home/aslam"
BRANCH="${1:-main}"
LOG_TAG="aslam-deploy"

cd "$ASLAM_DIR"

# Fetch and check if there are changes
git fetch origin "$BRANCH" 2>/dev/null
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "origin/$BRANCH")

if [ "$LOCAL" = "$REMOTE" ] && [ -f "$ASLAM_DIR/aslam" ]; then
    logger -t "$LOG_TAG" "Already up to date ($LOCAL)"
    exit 0
fi

logger -t "$LOG_TAG" "Updating $LOCAL -> $REMOTE"

git reset --hard "origin/$BRANCH"

# Build
go build -o "$ASLAM_DIR/aslam" .

logger -t "$LOG_TAG" "Build complete, restarting service"
systemctl restart aslam

logger -t "$LOG_TAG" "Deploy complete ($(git rev-parse --short HEAD))"
