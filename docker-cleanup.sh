#!/usr/bin/env bash
# docker-cleanup.sh
# Script to stop the application and clean up all residual Docker assets.

echo "Stopping XWA-SEC containers..."
docker compose down -v --remove-orphans

echo "Cleaning up dangling images and unused networks..."
# Remove dangling images (untagged)
docker image prune -f

# Specifically target the project containers if needed, but compose down -v handles volumes.
# If you want a more aggressive prune (WARNING: removes all unused docker cache):
# docker system prune -a --volumes -f

echo "Cleanup complete."
