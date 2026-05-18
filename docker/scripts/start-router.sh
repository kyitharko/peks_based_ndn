#!/usr/bin/env bash
set -e

PRODUCER_IP="10.10.0.3"
TRAPDOOR_DIR="${TRAPDOOR_DIR:-/shared}"

echo "[router] Starting NFD..."
cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf
nfd &
sleep 2

# Wait for the producer to finish writing the full trapdoor table.
# Producer writes td_ready.flag after all td_{row}_{col}.bin files are complete.
echo "[router] Waiting for trapdoor table (td_ready.flag in ${TRAPDOOR_DIR})..."
while [ ! -f "${TRAPDOOR_DIR}/td_ready.flag" ]; do sleep 1; done
echo "[router] Trapdoor table ready."

echo "[router] Creating face to producer (${PRODUCER_IP})..."
FACE_ID=$(nfdc face create "udp4://${PRODUCER_IP}:6363" | grep -oP '\bid=\K[0-9]+')
echo "[router] Face to producer: faceId=${FACE_ID}"

echo "[router] Adding FIB route /producer → producer..."
nfdc route add /producer "${FACE_ID}"

echo "[router] Setting PEKS strategy on /producer..."
nfdc strategy set /producer /localhost/nfd/strategy/peks/%FD%01

echo "[router] Ready. NFD routing table:"
nfdc route list

wait
