cmake_minimum_required(VERSION 3.20)

# Allow unsupported features for vcpkg (required for mysql-connector-cpp[jdbc] on windows-x64-dynamic)
set(VCPKG_INSTALL_OPTIONS "--allow-unsupported")

# Set Vcpkg Toolchain if not specified
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    # Try to find vcpkg from environment variable
    if(DEFINED ENV{VCPKG_ROOT})
        set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
        message(STATUS "Found vcpkg via VCPKG_ROOT: ${CMAKE_TOOLCHAIN_FILE}")
    # Fallback to local known path (Development convenience)
    elseif(EXISTS "H:/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE "H:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
        message(STATUS "Using local vcpkg: ${CMAKE_TOOLCHAIN_FILE}")
    else()
        message(STATUS "VCPKG toolchain not found. If you intend to use vcpkg, please set CMAKE_TOOLCHAIN_FILE or VCPKG_ROOT.")
    endif()
endif()

project(Bejeweled_Server)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Packages via vcpkg
# On Ubuntu, ensure you have vcpkg installed and pass -DCMAKE_TOOLCHAIN_FILE=...
find_package(Boost CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(unofficial-mysql-connector-cpp CONFIG REQUIRED)

# Gather source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Create executable
add_executable(Bejeweled_Server ${SOURCES})

# Link libraries
# Boost
target_link_libraries(Bejeweled_Server PRIVATE Boost::asio Boost::system Boost::bind Boost::date_time)

# OpenSSL
target_link_libraries(Bejeweled_Server PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# nlohmann_json
target_link_libraries(Bejeweled_Server PRIVATE nlohmann_json::nlohmann_json)

# MySQL
# Link JDBC (connector-jdbc)
if(TARGET unofficial::mysql-connector-cpp::connector-jdbc)
    target_link_libraries(Bejeweled_Server PRIVATE unofficial::mysql-connector-cpp::connector-jdbc)
endif()

# Windows system libraries
if(WIN32)
    target_link_libraries(Bejeweled_Server PRIVATE 
        ws2_32 
        mswsock 
        crypt32 
        secur32 
        bcrypt 
        advapi32
        dnsapi
        iphlpapi
        userenv
        version
    )
endif()

# Ubuntu/Linux specific configurations
if(UNIX AND NOT APPLE)
    # Add pthread if needed (often required for C++ networking/threading)
    find_package(Threads REQUIRED)
    target_link_libraries(Bejeweled_Server PRIVATE Threads::Threads)
    
    # If not using vcpkg for some libs, you might need to link dl, etc.
    # target_link_libraries(Bejeweled_Server PRIVATE dl)
endif()

message(STATUS "========================================")
message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "========================================")
