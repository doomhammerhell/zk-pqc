# syntax=docker/dockerfile:1.4
FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    git \
    nodejs \
    npm \
    pkg-config \
    libssl-dev \
    texlive-latex-base \
    texlive-fonts-recommended \
    texlive-fonts-extra \
    texlive-latex-extra \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Rust Builder
FROM base AS rust-builder
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup component add clippy rustfmt
RUN rustup toolchain install nightly

# Cairo/Scarb Builder
FROM rust-builder AS cairo-builder
RUN curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# Final Dev Environment
FROM cairo-builder AS dev-env
WORKDIR /workspace
COPY . .
RUN npm install || true
CMD ["/bin/bash"]
