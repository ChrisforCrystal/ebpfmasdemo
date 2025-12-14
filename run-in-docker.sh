#!/bin/bash
set -e

echo "=== 1. Building Docker Image (This may take a few minutes) ==="
docker build -f masdeepflow/Dockerfile -t masdeepflow:latest masdeepflow/

echo "=== 2. Running Agent in Container ==="
echo "Note: Running in privileged mode to access eBPF features."
echo "Once inside the container (or in a separate terminal exec), try:"
echo "  - docker logs -f masdeepflow-demo (to see logs)"

# Enable cleanup of previous failed runs
docker rm -f masdeepflow-demo 2>/dev/null || true

docker run --privileged \
  --name masdeepflow-demo \
  -d \
  -v /sys/kernel/debug:/sys/kernel/debug \
  masdeepflow:latest

echo "Container started in background."
echo "Waiting 3 seconds to check for immediate crash..."
sleep 3

if [ -z "$(docker ps -q -f name=masdeepflow-demo)" ]; then
    echo "❌ ERROR: Container exited prematurely! Showing logs:"
    echo "=================================================="
    docker logs masdeepflow-demo
    echo "=================================================="
    echo "Tip: The container was NOT removed. You can inspect it manually."
    exit 1
else
    echo "✅ Container is running successfully. ID: $(docker ps -q -f name=masdeepflow-demo)"
fi
