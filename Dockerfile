# syntax=docker/dockerfile:1

FROM rust:1.99.1-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends cmake && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
ENV CARGO_BUILD_JOBS=1

COPY Cargo.toml Cargo.lock ./
COPY tests/support/ tests/support/
COPY src/ src/

RUN cargo build --locked --release --bin shoes

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /build/target/release/shoes /usr/local/bin/shoes
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/doc/shoes/
COPY licenses/ /usr/share/doc/shoes/licenses/

WORKDIR /etc/shoes
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/shoes"]
CMD ["/etc/shoes/config.yaml"]
