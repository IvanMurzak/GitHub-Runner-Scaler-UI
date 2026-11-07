# The optional runner-manager coordinator (docs/coordinator.md).
#
# Build from the repository root:
#   docker build -f deploy/coordinator/Dockerfile -t runner-manager-coordinator .
#
# The image serves plain HTTP on 8080; TLS is terminated by the Caddy service
# in deploy/coordinator/docker-compose.yml.

# The toolchain rust-toolchain.toml pins.
FROM rust:1.94.0-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p runner-manager-coordinator \
    && cp target/release/runner-manager-coordinator /usr/local/bin/

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data --create-home coordinator
COPY --from=build /usr/local/bin/runner-manager-coordinator /usr/local/bin/
USER coordinator
WORKDIR /data
ENV COORDINATOR_LISTEN=0.0.0.0:8080 \
    COORDINATOR_DB=/data/coordinator.db
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["runner-manager-coordinator"]
CMD ["serve"]
