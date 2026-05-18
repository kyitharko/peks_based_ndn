# ════════════════════════════════════════════════════════════════════════
#  Stage 1 — builder: compile everything from source
#  This stage is discarded after building; only binaries are kept.
# ════════════════════════════════════════════════════════════════════════
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential cmake git pkg-config python3 \
    libboost-all-dev libssl-dev libsqlite3-dev \
    libgmp-dev libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# ── mcl ──────────────────────────────────────────────────────────────
RUN git clone --depth=1 https://github.com/herumi/mcl.git /opt/mcl \
    && cd /opt/mcl && make -j$(nproc) && make install && ldconfig

# ── ndn-cxx 0.8.1 ────────────────────────────────────────────────────
RUN git clone --depth=1 --branch ndn-cxx-0.8.1 \
    https://github.com/named-data/ndn-cxx.git /opt/ndn-cxx \
    && cd /opt/ndn-cxx \
    && ./waf configure --without-osx-keychain \
    && ./waf -j$(nproc) \
    && ./waf install \
    && ldconfig

# ── libpeks + producer/consumer binaries ─────────────────────────────
COPY ate_pairing.hpp ate_pairing.cpp peks.hpp peks.cpp /opt/peks/
COPY ate_pairing_test.cpp peks_test.cpp sim_peks_ndn.cpp /opt/peks/
COPY ndn/peks_name.hpp ndn/peks_name.cpp               /opt/peks/ndn/
COPY ndn/producer.cpp ndn/consumer.cpp                 /opt/peks/ndn/
COPY CMakeLists.txt                                    /opt/peks/
COPY ndn/CMakeLists.txt                                /opt/peks/ndn/
COPY data/names.txt                                    /opt/peks/data/names.txt

RUN cmake -S /opt/peks -B /opt/peks/build \
        -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /opt/peks/build -j$(nproc) \
    && cmake --install /opt/peks/build \
    && ldconfig

# ── NFD 22.12 with PeksStrategy injected into daemon/fw/ ─────────────
RUN git clone --depth=1 --branch NFD-22.12 --recursive \
    https://github.com/named-data/NFD.git /opt/NFD

COPY ndn/peks_strategy.hpp ndn/peks_strategy.cpp /opt/NFD/daemon/fw/
COPY ndn/peks_name.hpp ndn/peks_name.cpp          /opt/NFD/daemon/fw/
COPY ate_pairing.hpp ate_pairing.cpp               /opt/NFD/daemon/fw/
COPY peks.hpp peks.cpp                             /opt/NFD/daemon/fw/

RUN sed -i \
        -e 's|"../peks\.hpp"|"peks.hpp"|g' \
        -e 's|<nfd/daemon/fw/strategy\.hpp>|"strategy.hpp"|g' \
        /opt/NFD/daemon/fw/peks_name.hpp \
        /opt/NFD/daemon/fw/peks_strategy.hpp \
    && sed -i \
        -e 's|<nfd/daemon/fw/algorithm\.hpp>|"algorithm.hpp"|g' \
        /opt/NFD/daemon/fw/peks_strategy.cpp

RUN python3 - <<'EOF'
import pathlib, re

top = pathlib.Path('/opt/NFD/wscript')
text = top.read_text()

patched = re.sub(
    r"(bld\.program\(name='nfd'.*?use='daemon-objects[^']*')\)",
    r"\1,\n                lib=['mcl', 'gmp', 'gmpxx'])",
    text, count=1, flags=re.DOTALL,
)

if patched == text:
    raise RuntimeError("Could not find bld.program(name='nfd',...) in NFD wscript")

top.write_text(patched)
print("NFD wscript patched: added lib=['mcl','gmp','gmpxx'] to bld.program('nfd')")
EOF

RUN cd /opt/NFD \
    && ./waf configure \
    && ./waf -j$(nproc) \
    && ./waf install \
    && ldconfig

# ════════════════════════════════════════════════════════════════════════
#  Stage 2 — runtime-base: minimal image with prebuilt binaries
#  Installs only runtime shared libraries; no compiler, no source code.
# ════════════════════════════════════════════════════════════════════════
FROM ubuntu:22.04 AS runtime-base

ENV DEBIAN_FRONTEND=noninteractive

# System runtime shared libraries (no -dev packages)
RUN apt-get update && apt-get install -y \
    libboost-filesystem1.74.0 \
    libboost-program-options1.74.0 \
    libboost-system1.74.0 \
    libboost-thread1.74.0 \
    libboost-atomic1.74.0 \
    libboost-chrono1.74.0 \
    libboost-date-time1.74.0 \
    libboost-regex1.74.0 \
    libboost-log1.74.0 \
    libboost-stacktrace1.74.0 \
    libssl3 libsqlite3-0 libgmp10 libgmpxx4ldbl libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Prebuilt libraries and binaries from the builder stage
COPY --from=builder /usr/local/lib/    /usr/local/lib/
COPY --from=builder /usr/local/bin/nfd /usr/local/bin/nfdc /usr/local/bin/
RUN mkdir -p /usr/local/etc/ndn
COPY --from=builder /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/

RUN ldconfig

# ════════════════════════════════════════════════════════════════════════
#  Target: router  — NFD with PeksStrategy compiled in
# ════════════════════════════════════════════════════════════════════════
FROM runtime-base AS router

COPY docker/scripts/start-router.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 6363/udp 6363/tcp

CMD ["/start.sh"]

# ════════════════════════════════════════════════════════════════════════
#  Target: producer  — peks_producer + vanilla NFD
# ════════════════════════════════════════════════════════════════════════
FROM runtime-base AS producer

COPY --from=builder /usr/local/bin/peks_producer /usr/local/bin/
COPY --from=builder /opt/peks/data/names.txt     /data/names.txt

COPY docker/scripts/start-producer.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]

# ════════════════════════════════════════════════════════════════════════
#  Target: consumer  — peks_consumer + vanilla NFD
# ════════════════════════════════════════════════════════════════════════
FROM runtime-base AS consumer

COPY --from=builder /usr/local/bin/peks_consumer /usr/local/bin/
COPY --from=builder /opt/peks/data/names.txt     /data/names.txt

COPY docker/scripts/start-consumer.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]
