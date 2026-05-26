#!/usr/bin/env bash
set -e

ROUTER_IP="10.10.0.2"
SHARE_DIR="${SHARE_DIR:-/shared}"
NAMES_FILE="${NAMES_FILE:-/data/names.txt}"

echo "[producer] Starting NFD..."
cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf
nfd &
sleep 2

echo "[producer] Creating face to router (${ROUTER_IP})..."
nfdc face create "udp4://${ROUTER_IP}:6363"

echo "[producer] Clearing any stale keys, trapdoors, and flags from ${SHARE_DIR}..."
rm -f "${SHARE_DIR}"/pk.bin "${SHARE_DIR}"/td_ready.flag "${SHARE_DIR}"/router_ready.flag "${SHARE_DIR}"/td_*_*.bin

echo "[producer] Starting PEKS producer..."
echo "[producer]   Names file : ${NAMES_FILE}"
echo "[producer]   Share dir  : ${SHARE_DIR}"
exec peks_producer "${SHARE_DIR}" "${NAMES_FILE}"
