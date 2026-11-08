FROM ubuntu:26.04

ARG VERSION
LABEL org.opencontainers.image.title="Squid WireGuard proxy" \
      org.opencontainers.image.version="${VERSION}"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       squid wireguard-tools iproute2 nftables python3 apache2-utils \
       bind9-dnsutils curl ca-certificates tini \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin wg-dns \
    && rm -rf /var/lib/apt/lists/* /var/log/squid/*

COPY src/ /opt/proxy/
COPY VERSION /opt/proxy/VERSION

EXPOSE 3128/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD ["python3", "/opt/proxy/service.py", "healthcheck"]
ENTRYPOINT ["/usr/bin/tini", "--", "python3", "/opt/proxy/service.py"]
