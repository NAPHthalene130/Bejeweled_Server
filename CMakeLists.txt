cmake_minimum_required(VERSION 3.20)

# Allow unsupported features for vcpkg (required for mysql-connector-cpp[jdbc] on windows-x64-dynamic)
set(VCPKG_INSTALL_OPTIONS "--allow-unsupported")

# Set Vcpkg Toolchain if not specified
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(EXISTS "H:/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE "H:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
        message(STATUS "Using VCPKG toolchain: ${CMAKE_TOOLCHAIN_FILE}")
    elseif(WIN32)
        # Fallback or user prompt
        message(STATUS "VCPKG toolchain not found at default location.")
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
if(TARGET Boost::headers)
    target_link_libraries(Bejeweled_Server PRIVATE Boost::headers)
else()
    target_link_libraries(Bejeweled_Server PRIVATE Boost::boost)
endif()

# OpenSSL
target_link_libraries(Bejeweled_Server PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# nlohmann_json
target_link_libraries(Bejeweled_Server PRIVATE nlohmann_json::nlohmann_json)

# MySQL
# Link both X DevAPI (connector) and JDBC (connector-jdbc)
if(TARGET unofficial::mysql-connector-cpp::connector-jdbc)
    target_link_libraries(Bejeweled_Server PRIVATE unofficial::mysql-connector-cpp::connector-jdbc)
endif()
if(TARGET unofficial::mysql-connector-cpp::connector)
    target_link_libraries(Bejeweled_Server PRIVATE unofficial::mysql-connector-cpp::connector)
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
