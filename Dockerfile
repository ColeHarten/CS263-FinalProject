# Use the latest Ubuntu LTS as base
FROM ubuntu:24.04

# Prevent tzdata from prompting during installation
ENV DEBIAN_FRONTEND=noninteractive

# Update package list and install essential tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    lldb \
    gdb \
    cmake \
    git \
    vim \
    curl \
    wget \
    pkg-config \
    valgrind \
    llvm-18 \
    strace && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set default working directory
WORKDIR /workspace

# Default command: start a shell
CMD ["/bin/bash"]
