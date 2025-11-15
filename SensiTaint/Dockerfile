# Dockerfile for SensiTaint
FROM ubuntu:22.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Add LLVM repository and install essential packages
RUN apt-get update && apt-get install -y \
    software-properties-common \
    wget \
    gnupg \
    && wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
    && echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main" >> /etc/apt/sources.list.d/llvm.list \
    && apt-get update && apt-get install -y \
    build-essential \
    g++ \
    clang-18 \
    llvm-18 \
    llvm-18-dev \
    llvm-18-tools \
    libllvm18 \
    libc6-dev \
    libclang-18-dev \
    libclang-common-18-dev \
    make \
    git \
    curl \
    sudo \
    gdb \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/include/llvm-18/llvm /usr/include/llvm \
    && ln -s /usr/lib/llvm-18/include/clang /usr/include/clang \
    && ln -s /usr/bin/clang-18 /usr/bin/clang \
    && ln -s /usr/bin/clang++-18 /usr/bin/clang++ \
    && ln -s /usr/bin/llvm-config-18 /usr/bin/llvm-config

# Create a non-root user
RUN useradd -m -s /bin/bash dev && \
    echo "dev ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up core dump configuration for the container
RUN echo "kernel.core_pattern = core.%p" >> /etc/sysctl.conf && \
    echo "* soft core unlimited" >> /etc/security/limits.conf && \
    echo "* hard core unlimited" >> /etc/security/limits.conf

# Switch to the dev user
USER dev
WORKDIR /home/dev

# Set environment variables for LLVM
ENV LLVM_PREFIX=/usr
ENV PATH="/usr/bin:${PATH}"
ENV CPPFLAGS="-I/usr/include/llvm-18 -I/usr/include/clang-18"
ENV LDFLAGS="-L/usr/lib/llvm-18/lib"

# Enable core dumps in the shell
RUN echo "ulimit -c unlimited" >> /home/dev/.bashrc

# Set the working directory for the project
WORKDIR /home/dev/sensitaint

# Default command
CMD ["/bin/bash"]
