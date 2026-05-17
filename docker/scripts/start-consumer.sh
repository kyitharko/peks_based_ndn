#!/usr/bin/env bash
set -e

ROUTER_IP="10.10.0.2"
SHARE_DIR="${SHARE_DIR:-/shared}"

echo "[consumer] Starting NFD..."
nfd &
sleep 2

echo "[consumer] Creating face to router (${ROUTER_IP})..."
FACE_ID=$(nfdc face create "udp4://${ROUTER_IP}:6363" | grep -oP 'faceid=\K[0-9]+')

echo "[consumer] Setting default route to router (faceId=${FACE_ID})..."
nfdc route add / "${FACE_ID}"

echo "[consumer] Waiting for producer public key..."
while [ ! -f "${SHARE_DIR}/pk.bin" ]; do sleep 1; done
echo "[consumer] pk.bin found — sending encrypted Interest..."

exec peks_consumer "${SHARE_DIR}"
