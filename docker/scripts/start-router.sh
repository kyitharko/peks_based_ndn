#!/usr/bin/env bash
set -e

PRODUCER_IP="10.10.0.3"
TRAPDOOR_DIR="${TRAPDOOR_DIR:-/shared}"
NUM_TRAPDOORS=5          # must match number of NAME_COMPONENTS in producer.cpp

echo "[router] Starting NFD..."
nfd &
sleep 2

echo "[router] Waiting for trapdoors in ${TRAPDOOR_DIR}..."
for i in $(seq 0 $((NUM_TRAPDOORS - 1))); do
    while [ ! -f "${TRAPDOOR_DIR}/td_${i}.bin" ]; do sleep 1; done
    echo "[router] Trapdoor td_${i}.bin ready"
done

echo "[router] Creating face to producer (${PRODUCER_IP})..."
FACE_ID=$(nfdc face create "udp4://${PRODUCER_IP}:6363" | grep -oP 'faceid=\K[0-9]+')
echo "[router] Face to producer: faceId=${FACE_ID}"

echo "[router] Adding FIB route /peks → producer..."
nfdc route add /peks "${FACE_ID}"

echo "[router] Setting PEKS strategy on /peks..."
nfdc strategy set /peks /localhost/nfd/strategy/peks/%FD%01

echo "[router] Ready. NFD routing table:"
nfdc route list

wait
