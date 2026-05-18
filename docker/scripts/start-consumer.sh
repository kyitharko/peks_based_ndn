#!/usr/bin/env bash
set -e

ROUTER_IP="10.10.0.2"
SHARE_DIR="${SHARE_DIR:-/shared}"
NAMES_FILE="${NAMES_FILE:-/data/names.txt}"
QUERY_COUNT="${QUERY_COUNT:-5}"    # number of random URIs to query

echo "[consumer] Starting NFD..."
cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf
nfd &
sleep 2

echo "[consumer] Creating face to router (${ROUTER_IP})..."
FACE_ID=$(nfdc face create "udp4://${ROUTER_IP}:6363" | grep -oP '\bid=\K[0-9]+')

echo "[consumer] Setting default route to router (faceId=${FACE_ID})..."
nfdc route add / "${FACE_ID}"

# Wait for td_ready.flag: guarantees pk.bin and all td_{row}_{col}.bin are written,
# and the router has had time to load the full trapdoor table.
echo "[consumer] Waiting for trapdoor table (td_ready.flag)..."
while [ ! -f "${SHARE_DIR}/td_ready.flag" ]; do sleep 1; done
echo "[consumer] Trapdoor table ready."

echo "[consumer] Starting PEKS consumer..."
echo "[consumer]   Names file  : ${NAMES_FILE}"
echo "[consumer]   Query count : ${QUERY_COUNT}"
exec peks_consumer "${SHARE_DIR}" "${NAMES_FILE}" "${QUERY_COUNT}"
