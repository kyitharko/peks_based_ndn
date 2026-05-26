#!/usr/bin/env bash
set -e

# UPSTREAM_IP: next hop toward the producer (set per-router in docker-compose).
UPSTREAM_IP="${UPSTREAM_IP:?UPSTREAM_IP must be set}"
TRAPDOOR_DIR="${TRAPDOOR_DIR:-/shared}"
ROUTER_NAME="${HOSTNAME:-router}"

echo "[${ROUTER_NAME}] Starting NFD..."
cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf
nfd &
sleep 2

# Wait for producer to finish writing trapdoors AND registering its prefix.
# td_ready.flag is written inside the producer's setInterestFilter success
# callback, so seeing it guarantees the producer is fully listening.
echo "[${ROUTER_NAME}] Waiting for trapdoor table (td_ready.flag)..."
while [ ! -f "${TRAPDOOR_DIR}/td_ready.flag" ]; do sleep 1; done
echo "[${ROUTER_NAME}] Trapdoor table ready."

echo "[${ROUTER_NAME}] Creating face to upstream (${UPSTREAM_IP})..."
FACE_ID=$(nfdc face create "udp4://${UPSTREAM_IP}:6363" | grep -oP '\bid=\K[0-9]+')
echo "[${ROUTER_NAME}] Upstream face: faceId=${FACE_ID}"

echo "[${ROUTER_NAME}] Adding FIB route /producer → upstream..."
nfdc route add /producer "${FACE_ID}"

# Apply PeksStrategy only to Interests carrying the peks_strategy marker.
# Interests to /producer without peks_strategy use normal NDN forwarding.
echo "[${ROUTER_NAME}] Setting PEKS strategy on /producer/peks_strategy..."
nfdc strategy set /producer/peks_strategy /localhost/nfd/strategy/peks/%FD%01

echo "[${ROUTER_NAME}] Ready. FIB:"
nfdc route list

# Signal consumers that this router (and the producer) are fully ready.
# Consumers wait for router_ready.flag before sending any Interests.
touch "${TRAPDOOR_DIR}/router_ready.flag"
echo "[${ROUTER_NAME}] router_ready.flag written — consumers may start."

wait
