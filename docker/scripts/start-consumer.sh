#!/usr/bin/env bash
set -e

# ROUTER_IP: IP of this consumer's directly-connected router (set in docker-compose).
ROUTER_IP="${ROUTER_IP:?ROUTER_IP must be set}"
SHARE_DIR="${SHARE_DIR:-/shared}"
NAMES_FILE="${NAMES_FILE:-/data/names.txt}"
QUERY_COUNT="${QUERY_COUNT:-5}"    # 0 = all names; positive N = N random names
CONSUMER_ID="${CONSUMER_ID:-?}"

echo "[con${CONSUMER_ID}] Starting NFD..."
cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf
nfd &
sleep 2

echo "[con${CONSUMER_ID}] Creating face to router (${ROUTER_IP})..."
FACE_ID=$(nfdc face create "udp4://${ROUTER_IP}:6363" | grep -oP '\bid=\K[0-9]+')

echo "[con${CONSUMER_ID}] Setting default route to router (faceId=${FACE_ID})..."
nfdc route add / "${FACE_ID}"

# Wait for router_ready.flag — written by the router after it has:
#   1. loaded the full trapdoor table
#   2. added FIB route /producer → upstream
#   3. set PeksStrategy on /producer/peks_strategy
# This also implies td_ready.flag is set (router waits for it first),
# which means the producer prefix is registered and pk.bin is available.
echo "[con${CONSUMER_ID}] Waiting for router to be ready (router_ready.flag)..."
while [ ! -f "${SHARE_DIR}/router_ready.flag" ]; do sleep 1; done
echo "[con${CONSUMER_ID}] Router ready."

echo "[con${CONSUMER_ID}] Starting PEKS consumer..."
echo "[con${CONSUMER_ID}]   Names file  : ${NAMES_FILE}"
echo "[con${CONSUMER_ID}]   Query count : ${QUERY_COUNT} (0 = all)"
exec peks_consumer "${SHARE_DIR}" "${NAMES_FILE}" "${QUERY_COUNT}" "${CONSUMER_ID}"
