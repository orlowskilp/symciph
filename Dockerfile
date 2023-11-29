
# Stage 1: Build the symciph binary
FROM rust:latest AS builder

# Using cross-compilation for compatibility with Alpine Linux
ARG CC_TARGET=x86_64-unknown-linux-musl

WORKDIR /app

COPY . .

RUN \
    rustup target add ${CC_TARGET} && \
    cargo build --target ${CC_TARGET} --release

# Stage 2: Create a minimal runtime image
FROM alpine:latest AS runtime

WORKDIR /app

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/symciph .

ENTRYPOINT ["/app/symciph"]
