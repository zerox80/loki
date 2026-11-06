ARG DEBIAN_IMAGE=debian:trixie-slim
FROM ${DEBIAN_IMAGE} AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev make pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY Makefile LICENSE ./
COPY include/ include/
COPY src/ src/
COPY tests/unit/ tests/unit/
RUN make -j2 all test && strip --strip-unneeded build/loki

FROM ${DEBIAN_IMAGE} AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3t64 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /source/build/loki /usr/local/bin/loki
COPY --from=build /source/LICENSE /usr/share/doc/loki/LICENSE
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/loki"]
