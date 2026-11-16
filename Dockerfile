# syntax=docker/dockerfile:1
#
# keyward-server image: static-ish binary on distroless, runs as non-root,
# keeps its SQLite database in /data. Serve it behind a TLS reverse proxy
# (see docker-compose.yml and deploy/Caddyfile).

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
# Use the image's toolchain instead of downloading the one pinned for development.
RUN rm -f rust-toolchain.toml \
 && cargo build --release --locked -p keyward-server \
 && mkdir -p /out/data

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/keyward-server /usr/local/bin/keyward-server
COPY --from=build --chown=65532:65532 /out/data /data
ENV KW_BIND=0.0.0.0:8080 \
    KW_DATABASE_URL=sqlite:///data/keyward.db
VOLUME ["/data"]
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/keyward-server"]
