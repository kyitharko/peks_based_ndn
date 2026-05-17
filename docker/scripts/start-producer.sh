#!/usr/bin/env bash
set -e

ROUTER_IP="10.10.0.2"
SHARE_DIR="${SHARE_DIR:-/shared}"

echo "[producer] Starting NFD..."
nfd &
sleep 2

echo "[producer] Creating face to router (${ROUTER_IP})..."
nfdc face create "udp4://${ROUTER_IP}:6363"

echo "[producer] Starting PEKS producer (generates keys + trapdoors → ${SHARE_DIR})..."
exec peks_producer "${SHARE_DIR}"
