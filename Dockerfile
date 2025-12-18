# Use Ubuntu 22.04 LTS as the base image
FROM ubuntu:22.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Update package list and install build dependencies
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

# Copy the project files
COPY . .

# Create build directory
RUN mkdir -p build

# Build the project
WORKDIR /app/build
RUN cmake .. && make -j$(nproc)

# Expose the server port
EXPOSE 10086

# Run the server
# You should pass environment variables for DB connection at runtime
CMD ["./Bejeweled_Server"]
