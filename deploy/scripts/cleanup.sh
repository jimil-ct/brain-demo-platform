#!/bin/bash
# Deployment cleanup script
# Removes stale containers and old artifacts

set -e

echo "Cleaning up old deployments..."

# Remove old Docker images
docker image prune -af --filter "until=72h"

# Clear build cache
rm -rf /opt/app/build/cache/*
rm -rf /tmp/deploy-artifacts-*

# Reset failed service state
systemctl reset-failed payment-worker billing-cron

echo "Cleanup complete."
