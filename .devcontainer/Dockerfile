FROM mcr.microsoft.com/devcontainers/base:noble

RUN apt-get update && apt install -y unminimize && yes | unminimize

# Install LLVM 18
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
COPY <<EOF /etc/apt/sources.list.d/llvm.sources
Types: deb deb-src
URIs: http://apt.llvm.org/noble/
Suites: llvm-toolchain-noble-18
Components: main
Signed-By: /etc/apt/trusted.gpg.d/apt.llvm.org.asc
EOF
RUN apt-get update && \
    apt-get install -y \
    clang-format clang-tidy clang-tools clang clangd libc++-dev libc++1 \
    libc++abi-dev libc++abi1 libclang-dev libclang1 liblldb-dev \
    libllvm-ocaml-dev libomp-dev libomp5 lld lldb llvm-dev llvm-runtime llvm \
    python3-clang

# Install Rust
USER vscode
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain none -y
RUN . "$HOME/.cargo/env" && rustup toolchain install nightly --allow-downgrade --profile minimal --component clippy
USER root

# Dependencies
RUN apt-get update && \
    apt-get install -y \
        vim \
        cpio \
        ninja-build \
        automake \
        autoconf \
        python3 \
        python3-pip \
        python-is-python3 \
        gcc-13-plugin-dev \
        libcapstone-dev \
        build-essential \
        python3-dev \
        cmake \
        git \
        flex \
        bison \
        libglib2.0-dev \
        libpixman-1-dev \
        python3-setuptools \
        libgtk-3-dev \
        libgtk-3-dev \
        pax-utils \
        python3-msgpack \
        python3-jinja2 \
        libcapstone-dev \
        libtool \
        gdb \
        tmux \
        binutils-dev \
        libunwind-dev \
        libblocksruntime-dev \
        gh

# Install Rust project dependencies
USER vscode
RUN . "$HOME/.cargo/env" && cargo install cargo-make
RUN . "$HOME/.cargo/env" && cargo install afl_runner
RUN . "$HOME/.cargo/env" && cargo install just
USER root
