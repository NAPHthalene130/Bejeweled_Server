# ========== Build Stage ==========
FROM ubuntu:22.04 AS builder

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libboost-all-dev \
    libssl-dev \
    libmysqlcppconn-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build the project
RUN mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)

# ========== Runtime Stage ==========
FROM ubuntu:22.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
# We install the dev packages or libraries needed for runtime execution
RUN apt-get update && apt-get install -y \
    libboost-system-dev \
    libboost-thread-dev \
    libssl-dev \
    libmysqlcppconn-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the executable from the builder stage
COPY --from=builder /app/build/Bejeweled_Server .

# Expose the server port
EXPOSE 10086

# Run the server
CMD ["./Bejeweled_Server"]
