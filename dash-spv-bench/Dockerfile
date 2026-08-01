FROM debian:bookworm-slim

ARG DASHVERSION=23.1.7

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Download the Linux dashd matching the host CPU arch (amd64 -> x86_64, arm64 -> aarch64).
# The version is pinned so benchmark numbers stay comparable; run.sh and snapshot-chain.sh tag the
# image with it and pass it back as --build-arg, so bumping it there rebuilds instead of reusing.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) dlarch=x86_64 ;; \
      arm64) dlarch=aarch64 ;; \
      *) echo "unsupported arch $arch" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/dashpay/dash/releases/download/v${DASHVERSION}/dashcore-${DASHVERSION}-${dlarch}-linux-gnu.tar.gz"; \
    curl -fsSL "$url" -o /tmp/dashcore.tgz; \
    tar -xzf /tmp/dashcore.tgz -C /tmp; \
    cp "/tmp/dashcore-${DASHVERSION}/bin/dashd" /usr/local/bin/dashd; \
    rm -rf /tmp/dashcore*; \
    dashd --version | head -1
