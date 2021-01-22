FROM rust:1.47.0 AS builder
RUN apt-get update && apt-get install -y cmake
COPY . lighthouse
ARG PORTABLE
ENV PORTABLE $PORTABLE
RUN cd lighthouse && RUSTFLAGS='-C force-frame-pointers=y' cargo install --path lighthouse --force --locked --features portable

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
  libssl-dev \
  ca-certificates linux-perf linux-base \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/lighthouse /usr/local/bin/lighthouse
