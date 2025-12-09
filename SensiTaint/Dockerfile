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
    && echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-15 main" >> /etc/apt/sources.list.d/llvm.list \
    && apt-get update && apt-get install -y \
    build-essential \
    g++ \
    clang-15 \
    clangd-12 \
    llvm-15 \
    llvm-15-dev \
    llvm-15-tools \
    libllvm15 \
    libc6-dev \
    libclang-15-dev \
    libclang-common-15-dev \
    make \
    git \
    curl \
    sudo \
    gdb \
    # PhASAR / CMake deps
    cmake \
    python3 \
    python3-pip \
    libz-dev \
    libsqlite3-dev \
    libncurses5-dev \
    libtinfo-dev \
    libedit-dev \
    libxml2-dev \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/include/llvm-15/llvm /usr/include/llvm \
    && ln -s /usr/lib/llvm-15/include/clang /usr/include/clang \
    && ln -s /usr/bin/clang-15 /usr/bin/clang \
    && ln -s /usr/bin/clang++-15 /usr/bin/clang++ \
    && ln -s /usr/bin/llvm-config-15 /usr/bin/llvm-config

RUN apt-get update && apt-get install -y nlohmann-json3-dev

# Remove old cmake and install a recent one from Kitware
RUN apt-get remove -y cmake || true \
 && apt-get update && apt-get install -y \
      ca-certificates \
      gpg \
      wget \
 && wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc \
      | gpg --dearmor -o /usr/share/keyrings/kitware-archive-keyring.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] \
      https://apt.kitware.com/ubuntu/ jammy main" \
      > /etc/apt/sources.list.d/kitware.list \
 && apt-get update \
 && apt-get install -y cmake \
 && cmake --version

# Create a non-root user
RUN useradd -m -s /bin/bash dev && \
    echo "dev ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up core dump configuration for the container
RUN echo "kernel.core_pattern = core.%p" >> /etc/sysctl.conf && \
    echo "* soft core unlimited" >> /etc/security/limits.conf && \
    echo "* hard core unlimited" >> /etc/security/limits.conf

# Install PhASAR from source (library & CLI)
RUN git clone --recursive https://github.com/secure-software-engineering/phasar.git /opt/phasar \
 && cd /opt/phasar \
 && cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_STANDARD=17 \
      -DLLVM_DIR=/usr/lib/llvm-15/cmake \
      -DCLANG_DIR=/usr/lib/llvm-15/lib/cmake/clang \
      -DPHASAR_BUILD_TESTS=OFF \
      -DPHASAR_BUILD_UNITTESTS=OFF \
      -DPHASAR_BUILD_EXAMPLES=OFF \
      -DPHASAR_BUILD_DOCS=OFF \
      -DPHASAR_BUILD_TOOLS=OFF \
 && cmake --build build --target phasar -- -j1 \
 && cmake --install build --prefix /opt/phasar/install

# Switch to the dev user
USER dev
WORKDIR /home/dev

# Set environment variables for LLVM
ENV LLVM_PREFIX=/usr
ENV PATH="/usr/bin:${PATH}"
ENV CPPFLAGS="-I/usr/include/llvm-15 -I/usr/include/clang-15"
ENV LDFLAGS="-L/usr/lib/llvm-15/lib"

# Set environment variables for phASAR
ENV PHASAR_ROOT=/opt/phasar/install
ENV CMAKE_PREFIX_PATH="${PHASAR_ROOT}:${CMAKE_PREFIX_PATH}"
ENV LD_LIBRARY_PATH="${PHASAR_ROOT}/lib:${LD_LIBRARY_PATH}"

# Enable core dumps in the shell
RUN echo "ulimit -c unlimited" >> /home/dev/.bashrc

# Set the working directory for the project
WORKDIR /home/dev/sensitaint

# Default command
CMD ["/bin/bash"]