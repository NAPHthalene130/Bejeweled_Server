cmake_minimum_required(VERSION 3.20)

# Function to read .env file
function(read_env_file FILENAME)
    message(STATUS "Attempting to read .env file from: ${FILENAME}")
    if(EXISTS "${FILENAME}")
        file(STRINGS "${FILENAME}" ENV_LINES)
        foreach(LINE IN LISTS ENV_LINES)
            message(STATUS "Processing line: ${LINE}")
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
            else()
                message(STATUS "Ignored line (no match): ${LINE}")
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

# If VS_DIR is defined, add it to CMAKE_PREFIX_PATH to help find libraries
if(DEFINED VS_DIR)
    list(APPEND CMAKE_PREFIX_PATH "${VS_DIR}")
    message(STATUS "Added VS_DIR to CMAKE_PREFIX_PATH: ${VS_DIR}")
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

# ==================== MySQL配置部分 ====================
if(MSVC)
    # 对于MSVC，使用预编译的MySQL Connector/C++ 9.5.0
    if(NOT DEFINED MYSQL_ROOT_DIR)
        message(FATAL_ERROR "MYSQL_ROOT_DIR is not defined in .env file.")
    endif()
    
    message(STATUS "MySQL root directory: ${MYSQL_ROOT_DIR}")
    
    if(NOT EXISTS "${MYSQL_ROOT_DIR}")
        message(FATAL_ERROR "MYSQL_ROOT_DIR does not exist: ${MYSQL_ROOT_DIR}")
    endif()
    
    # 查找include目录
    set(POSSIBLE_INCLUDE_DIRS
        "${MYSQL_ROOT_DIR}/include"
        "${MYSQL_ROOT_DIR}/include/mysql"
        "${MYSQL_ROOT_DIR}/include/mysql-cppconn-9"
        "${MYSQL_ROOT_DIR}/include/mysql-cppconn-8"
    )
    
    set(MYSQL_INCLUDE_DIR "")
    foreach(dir IN LISTS POSSIBLE_INCLUDE_DIRS)
        if(EXISTS "${dir}")
            if(EXISTS "${dir}/mysql_driver.h" OR EXISTS "${dir}/mysqlx/xdevapi.h")
                set(MYSQL_INCLUDE_DIR "${dir}")
                message(STATUS "Found MySQL include directory: ${MYSQL_INCLUDE_DIR}")
                break()
            endif()
        endif()
    endforeach()
    
    if(NOT MYSQL_INCLUDE_DIR)
        message(FATAL_ERROR "Could not find MySQL include directory")
    endif()
    
    # 使用.env中定义的MYSQL_LIB_DIR
    if(NOT DEFINED MYSQL_LIB_DIR OR NOT EXISTS "${MYSQL_LIB_DIR}")
        message(FATAL_ERROR "MYSQL_LIB_DIR not found or invalid")
    endif()
    
    message(STATUS "Using MySQL library directory: ${MYSQL_LIB_DIR}")
    
    # 设置库文件路径
    set(MYSQL_LIBRARY_JDBC_DYNAMIC "${MYSQL_LIB_DIR}/mysqlcppconn.lib")
    set(MYSQL_LIBRARY_XDEVAPI_DYNAMIC "${MYSQL_LIB_DIR}/mysqlcppconnx.lib")
    
    if(EXISTS "${MYSQL_LIBRARY_JDBC_DYNAMIC}" AND EXISTS "${MYSQL_LIBRARY_XDEVAPI_DYNAMIC}")
        set(MYSQL_LIBRARY_JDBC "${MYSQL_LIBRARY_JDBC_DYNAMIC}")
        set(MYSQL_LIBRARY_XDEVAPI "${MYSQL_LIBRARY_XDEVAPI_DYNAMIC}")
        set(MYSQL_STATIC FALSE)
        message(STATUS "Using MySQL dynamic libraries for MSVC")
    else()
        message(FATAL_ERROR "MySQL dynamic libraries not found in ${MYSQL_LIB_DIR}")
    endif()
    
    set(MySQL_FOUND TRUE)
    set(MySQL_INCLUDE_DIRS ${MYSQL_INCLUDE_DIR})
    set(MySQL_LIBRARIES ${MYSQL_LIBRARY_JDBC} ${MYSQL_LIBRARY_XDEVAPI})
    set(MYSQL_STATIC FALSE)
    
elseif(MINGW)
    # 对于MinGW，使用vcpkg安装的MySQL Connector/C++静态库
    message(WARNING "MinGW build is selected. For better Windows compatibility, consider using MSVC.")
    find_package(unofficial-mysql-connector-cpp CONFIG REQUIRED)
    set(MYSQL_STATIC TRUE)
    set(MySQL_FOUND TRUE)
    # 使用target自动包含头文件
    set(MySQL_INCLUDE_DIRS "")
    set(MySQL_LIBRARIES unofficial::mysql-connector-cpp::connector)
    
    # 为静态链接添加定义
    add_definitions(-DSTATIC_CONCPP)
    
else()
    message(FATAL_ERROR "Unsupported compiler. Only MSVC and MinGW are supported.")
endif()

message(STATUS "MySQL found: ${MySQL_FOUND}")
if(MySQL_FOUND)
    message(STATUS "MySQL static: ${MYSQL_STATIC}")
    if(MSVC)
        message(STATUS "MySQL include dir: ${MySQL_INCLUDE_DIRS}")
        message(STATUS "MySQL libraries: ${MySQL_LIBRARIES}")
    else()
        message(STATUS "Using vcpkg MySQL Connector/C++ package")
    endif()
endif()
# ==================== MySQL配置结束 ====================

# Find Boost
find_package(Boost REQUIRED)

# Include directories
include_directories(include)
include_directories(${Boost_INCLUDE_DIRS})
if(MSVC)
    include_directories(${MySQL_INCLUDE_DIRS})
endif()

# Gather source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Create executable
add_executable(Bejeweled_Server ${SOURCES})

# Link libraries
if(TARGET Boost::boost)
    target_link_libraries(Bejeweled_Server PRIVATE Boost::boost)
elseif(TARGET Boost::headers)
    target_link_libraries(Bejeweled_Server PRIVATE Boost::headers)
else()
    target_include_directories(Bejeweled_Server PRIVATE ${Boost_INCLUDE_DIRS})
endif()

# 链接MySQL库
target_link_libraries(Bejeweled_Server PRIVATE ${MySQL_LIBRARIES})

# 对于Windows，添加必要的系统库
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

# 如果使用静态库，还需要链接其他库
if(MYSQL_STATIC AND WIN32)
    target_link_libraries(Bejeweled_Server PRIVATE
        rpcrt4
        wldap32
        normaliz
    )
endif()

# 复制MySQL DLL到输出目录（仅Windows MSVC且动态链接）
if(MSVC AND WIN32 AND NOT MYSQL_STATIC)
    if(DEFINED MYSQL_ROOT_DIR)
        # 查找bin目录
        set(POSSIBLE_BIN_DIRS
            "${MYSQL_ROOT_DIR}/bin"
            "${MYSQL_ROOT_DIR}/bin64"
            "${MYSQL_ROOT_DIR}/lib64"
            "${MYSQL_ROOT_DIR}/lib"
        )
        
        set(MYSQL_BIN_DIR "")
        foreach(dir IN LISTS POSSIBLE_BIN_DIRS)
            if(EXISTS "${dir}")
                set(MYSQL_BIN_DIR "${dir}")
                message(STATUS "Found MySQL binary directory: ${MYSQL_BIN_DIR}")
                break()
            endif()
        endforeach()
        
        if(MYSQL_BIN_DIR)
            # 明确指定需要复制的DLL列表 (针对 Connector/C++ 9.5.0)
            set(REQUIRED_DLLS
                "mysqlcppconn-10-vs14.dll"
                "mysqlcppconnx-2-vs14.dll"
                "libcrypto-3-x64.dll"
                "libssl-3-x64.dll"
            )
            
            # 尝试复制每个DLL
            foreach(dll_name IN LISTS REQUIRED_DLLS)
                # 先在bin目录找
                set(dll_path "${MYSQL_BIN_DIR}/${dll_name}")
                if(NOT EXISTS "${dll_path}")
                    # 找不到再去lib64目录找 (Connector/C++ 9.5 似乎把部分dll放在lib64)
                    set(dll_path "${MYSQL_ROOT_DIR}/lib64/${dll_name}")
                endif()

                if(EXISTS "${dll_path}")
                    add_custom_command(TARGET Bejeweled_Server POST_BUILD
                        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${dll_path}"
                        $<TARGET_FILE_DIR:Bejeweled_Server>
                        COMMENT "Copying ${dll_name}"
                    )
                    message(STATUS "Configured to copy ${dll_name}")
                else()
                    message(WARNING "Could not find DLL: ${dll_name} in ${MYSQL_BIN_DIR} or lib64")
                endif()
            endforeach()
        endif()
    endif()
endif()

# 打印配置摘要
message(STATUS "========================================")
message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Boost found: ${Boost_FOUND}")
message(STATUS "MySQL found: ${MySQL_FOUND}")
if(MySQL_FOUND)
    message(STATUS "MySQL static: ${MYSQL_STATIC}")
endif()
message(STATUS "========================================")
