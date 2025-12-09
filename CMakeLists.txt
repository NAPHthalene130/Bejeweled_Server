cmake_minimum_required(VERSION 3.20)

# Function to read .env file
function(read_env_file FILENAME)
    if(EXISTS "${FILENAME}")
        file(STRINGS "${FILENAME}" ENV_LINES)
        foreach(LINE IN LISTS ENV_LINES)
            # Skip comments and empty lines
            if(LINE MATCHES "^#" OR LINE STREQUAL "")
                continue()
            endif()
            # Match key=value
            if(LINE MATCHES "^([^=]+)=(.*)$")
                set(KEY "${CMAKE_MATCH_1}")
                set(VALUE "${CMAKE_MATCH_2}")
                string(STRIP "${KEY}" KEY)
                string(STRIP "${VALUE}" VALUE)
                # Remove quotes if present
                string(REGEX REPLACE "^\"(.*)\"$" "\\1" VALUE "${VALUE}")
                string(REGEX REPLACE "^'(.*)'$" "\\1" VALUE "${VALUE}")
                
                set(${KEY} "${VALUE}" PARENT_SCOPE)
                message(STATUS "Loaded env var from .env: ${KEY}=${VALUE}")
            endif()
        endforeach()
    else()
        message(WARNING ".env file not found at ${FILENAME}")
    endif()
endfunction()

# Load environment variables from .vscode/.env
read_env_file("${CMAKE_CURRENT_SOURCE_DIR}/.vscode/.env")

# Set VCPKG toolchain if VCPKG_DIR is defined
if(DEFINED VCPKG_DIR)
    set(CMAKE_TOOLCHAIN_FILE "${VCPKG_DIR}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
    message(STATUS "Using VCPKG toolchain: ${CMAKE_TOOLCHAIN_FILE}")
endif()

project(Bejeweled_Server)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set Boost root if defined
if(DEFINED BOOST_ROOT)
    set(Boost_ROOT "${BOOST_ROOT}")
    set(BOOST_ROOT "${BOOST_ROOT}") # Set both for compatibility
    message(STATUS "Using Boost root: ${BOOST_ROOT}")
endif()

# Find Boost
find_package(Boost REQUIRED)

# Include directories
include_directories(${Boost_INCLUDE_DIRS})

# Gather source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Create executable
add_executable(Bejeweled_Server ${SOURCES})

# Link libraries
# target_link_libraries(Bejeweled_Server PRIVATE ${Boost_LIBRARIES}) 
# Uncomment above if you need to link against Boost libraries (e.g. filesystem, system, etc.)
# For header-only Boost libs, it might not be strictly necessary depending on CMake version/targets, 
# but usually good practice to link Boost::boost or similar if available.
if(TARGET Boost::boost)
    target_link_libraries(Bejeweled_Server PRIVATE Boost::boost)
elseif(TARGET Boost::headers)
    target_link_libraries(Bejeweled_Server PRIVATE Boost::headers)
else()
    target_include_directories(Bejeweled_Server PRIVATE ${Boost_INCLUDE_DIRS})
endif()

if(WIN32)
    target_link_libraries(Bejeweled_Server PRIVATE ws2_32 mswsock)
endif()
