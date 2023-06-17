FROM rust:alpine3.17 as builder

# update packages
RUN apk update
RUN apk add build-base openssl-dev ca-certificates

# create root application folder
WORKDIR /app

COPY ./ /app/src

# Install rust toolchains
RUN rustup toolchain install stable
RUN rustup default stable

WORKDIR /app/src

# Build dependencies only. Separate these for caches
RUN cargo install cargo-build-deps
RUN cargo build-deps --release

# Build the release executable.
RUN cargo build --release

# Runner stage. I tried using distroless (gcr.io/distroless/static-debian11), but the image was only ~3MBs smaller than
# alpine. I chose to use alpine since a user can easily be added to the image.
FROM alpine:3.17

ARG UNAME=orca-registry
ARG UID=1000
ARG GID=1000

# Add user and copy the executable from the build stage.
RUN adduser --disabled-password --gecos "" $UNAME -s -G $GID -u $UID
COPY --from=builder --chown=$UID:$GID /app/src/target/release/orca-registry /app/orca-registry

RUN mkdir /data && \
    chown -R $UID:$GID /data && \
    chown -R $UID:$GID /app

USER $UNAME

WORKDIR /app/

EXPOSE 3000

ENTRYPOINT [ "/app/orca-registry" ]