FROM mcr.microsoft.com/devcontainers/rust:1-1.82-bookworm

# Install tools tambahan yang dibutuhkan untuk STARK proving / build
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends build-essential clang llvm pkg-config libssl-dev \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*