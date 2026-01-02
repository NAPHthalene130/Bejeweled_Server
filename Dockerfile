# ========== Build Stage ==========
FROM ubuntu:22.04 AS builder

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV VCPKG_ROOT=/opt/vcpkg
ENV CMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake

# Install build dependencies and tools for vcpkg
# We need curl, zip, etc. for vcpkg to download ports
# We need build-essential, cmake, etc. for building
# bison/flex might be needed for mysql-connector build
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
    zip \
    unzip \
    tar \
    pkg-config \
    linux-libc-dev \
    ninja-build \
    autoconf \
    automake \
    libtool \
    bison \
    flex \
    && rm -rf /var/lib/apt/lists/*

# Clone and bootstrap vcpkg
WORKDIR /opt
RUN git clone https://github.com/microsoft/vcpkg.git && \
    ./vcpkg/bootstrap-vcpkg.sh

# Install dependencies using vcpkg
# We copy vcpkg.json first to leverage Docker cache for dependencies
WORKDIR /app
COPY vcpkg.json .

# Pre-install dependencies to cache them
# Note: implicit manifest mode in cmake would also do this, but explicit install is better for layer caching
RUN ${VCPKG_ROOT}/vcpkg install --triplet x64-linux --allow-unsupported

# Copy source code
COPY . .

# Build the project
RUN mkdir -p build && cd build && \
    cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
    -DCMAKE_BUILD_TYPE=Release \
    -DVCPKG_TARGET_TRIPLET=x64-linux \
    && \
    make -j$(nproc)

# ========== Runtime Stage ==========
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
# We install basic runtime libs. 
# Since we use vcpkg dynamic libs, we will copy them.
# libssl3 and ca-certificates are generally useful.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the executable from the builder stage
COPY --from=builder /app/build/Bejeweled_Server .

# Copy dynamic libraries built by vcpkg
# We copy them to a specific directory and add it to LD_LIBRARY_PATH
COPY --from=builder /app/build/vcpkg_installed/x64-linux/lib /app/libs

# Copy any other necessary resources (like config templates if needed, though usually configs are passed via env)
# COPY --from=builder /app/.vscode/.env.template ./.env.template

# Set library path
ENV LD_LIBRARY_PATH=/app/libs:$LD_LIBRARY_PATH

# Expose the server ports
# AuthServer: 10086
# OtherServer: 10088
# GameServer: 10090
EXPOSE 10086 10088 10090

# Run the server
CMD ["./Bejeweled_Server"]
