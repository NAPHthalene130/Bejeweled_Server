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

project(Bejeweled_Server)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set Boost root if defined
if(DEFINED BOOST_ROOT)
    set(Boost_ROOT "${BOOST_ROOT}")
    set(BOOST_ROOT "${BOOST_ROOT}") # Set both for compatibility
    message(STATUS "Using Boost root: ${BOOST_ROOT}")
endif()

# ==================== MySQL配置部分 - 增强版 ====================
if(NOT DEFINED MYSQL_ROOT_DIR)
    message(WARNING "MYSQL_ROOT_DIR is not defined in .env file.")
    
    # 尝试系统默认路径
    if(WIN32)
        # 尝试多个可能的默认路径
        set(POSSIBLE_PATHS
            "C:/Program Files/MySQL/MySQL Connector C++ 8.0"
            "C:/Program Files/MySQL/MySQL Connector C++ 9.0"
            "C:/MySQL/connector-c++"
        )
        
        foreach(path IN LISTS POSSIBLE_PATHS)
            if(EXISTS "${path}")
                set(MYSQL_ROOT_DIR "${path}")
                break()
            endif()
        endforeach()
    endif()
    
    if(NOT DEFINED MYSQL_ROOT_DIR)
        message(FATAL_ERROR "MYSQL_ROOT_DIR not set. Please add MYSQL_ROOT_DIR to .env file")
    endif()
endif()

message(STATUS "MySQL root directory: ${MYSQL_ROOT_DIR}")

# 验证MYSQL_ROOT_DIR是否存在
if(NOT EXISTS "${MYSQL_ROOT_DIR}")
    message(FATAL_ERROR "MYSQL_ROOT_DIR does not exist: ${MYSQL_ROOT_DIR}")
endif()

# 查找include目录
set(POSSIBLE_INCLUDE_DIRS
    "${MYSQL_ROOT_DIR}/include"                          # 默认路径 (应包含 mysql_driver.h)
    "${MYSQL_ROOT_DIR}/include/mysql"                    # 某些版本会多一层 mysql 目录
    "${MYSQL_ROOT_DIR}/include/mysql-cppconn-9"
    "${MYSQL_ROOT_DIR}/include/mysql-cppconn-8"
)

set(MYSQL_INCLUDE_DIR "")
foreach(dir IN LISTS POSSIBLE_INCLUDE_DIRS)
    if(EXISTS "${dir}")
        # 额外检查关键文件是否存在，确认这是一个正确的包含目录
        if(EXISTS "${dir}/mysql_driver.h" OR EXISTS "${dir}/mysqlx/xdevapi.h")
            set(MYSQL_INCLUDE_DIR "${dir}")
            message(STATUS "Found MySQL include directory: ${MYSQL_INCLUDE_DIR}")
            break()
        endif()
    endif()
endforeach()

if(NOT DEFINED MYSQL_INCLUDE_DIR)
    message(FATAL_ERROR "Could not find MySQL include directory in any expected location")
endif()

# 查找库目录 - 尝试多个可能的路径
set(POSSIBLE_LIB_DIRS
    "${MYSQL_ROOT_DIR}/lib64/vs16"      # VS2019
    "${MYSQL_ROOT_DIR}/lib64/vs15"      # VS2017
    "${MYSQL_ROOT_DIR}/lib64/vs14"      # VS2015 <--- 您的 .env 文件指向这里
    "${MYSQL_ROOT_DIR}/lib64"
    "${MYSQL_ROOT_DIR}/lib/vs16"
    "${MYSQL_ROOT_DIR}/lib/vs15"
    "${MYSQL_ROOT_DIR}/lib/vs14"
    "${MYSQL_ROOT_DIR}/lib"
)

# 使用 .env 中定义的 MYSQL_LIB_DIR (如果存在)
if(DEFINED MYSQL_LIB_DIR AND EXISTS "${MYSQL_LIB_DIR}")
    message(STATUS "Using explicitly defined MySQL library directory: ${MYSQL_LIB_DIR}")
else()
    set(MYSQL_LIB_DIR "")
    foreach(dir IN LISTS POSSIBLE_LIB_DIRS)
        if(EXISTS "${dir}")
            set(MYSQL_LIB_DIR "${dir}")
            message(STATUS "Found MySQL library directory: ${MYSQL_LIB_DIR}")
            break()
        endif()
    endforeach()
endif()

if(NOT MYSQL_LIB_DIR)
    message(FATAL_ERROR "Could not find MySQL library directory in any expected location")
endif()

# 可能的库文件名（对于9.5.0版本）
set(POSSIBLE_LIB_NAMES
    mysqlcppconn9        # 9.x版本的动态库
    mysqlcppconn8        # 8.x版本的动态库
    mysqlcppconn         # 通用名称
    libmysqlcppconn9     # 带lib前缀
    libmysqlcppconn8
    libmysqlcppconn
    mysqlcppconn9-static # 静态库
    mysqlcppconn8-static
    mysqlcppconn-static
)

# 查找库文件
find_library(MYSQL_LIBRARY
    NAMES ${POSSIBLE_LIB_NAMES}
    PATHS ${MYSQL_LIB_DIR}
    NO_DEFAULT_PATH
)

if(NOT MYSQL_LIBRARY)
    # 列出库目录中的文件以帮助调试
    message(STATUS "Contents of MySQL library directory ${MYSQL_LIB_DIR}:")
    file(GLOB LIB_FILES "${MYSQL_LIB_DIR}/*")
    foreach(file IN LISTS LIB_FILES)
        get_filename_component(file_name "${file}" NAME)
        message(STATUS "  ${file_name}")
    endforeach()
    
    message(FATAL_ERROR "Could not find MySQL library in ${MYSQL_LIB_DIR}. "
            "Available files listed above. Please check the library name."
    )
endif()

message(STATUS "Found MySQL library: ${MYSQL_LIBRARY}")

# 判断是否为静态库
get_filename_component(LIB_NAME "${MYSQL_LIBRARY}" NAME)
if(LIB_NAME MATCHES "static" OR LIB_NAME MATCHES "Static")
    set(MYSQL_STATIC TRUE)
    message(STATUS "MySQL library is static")
else()
    set(MYSQL_STATIC FALSE)
    message(STATUS "MySQL library is dynamic")
endif()

set(MySQL_FOUND TRUE)
set(MySQL_INCLUDE_DIRS ${MYSQL_INCLUDE_DIR})
set(MySQL_LIBRARIES ${MYSQL_LIBRARY})
# ==================== MySQL配置结束 ====================

# Find Boost
find_package(Boost REQUIRED)

# Include directories
include_directories(include)
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${MySQL_INCLUDE_DIRS}) # <--- 最终添加包含路径

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

# 静态链接MySQL需要额外的依赖库
if(MYSQL_STATIC)
    message(STATUS "Adding static MySQL dependencies")
    if(WIN32)
        target_link_libraries(Bejeweled_Server PRIVATE
            ws2_32
            crypt32
            secur32
            bcrypt
            advapi32
        )
    else()
        target_link_libraries(Bejeweled_Server PRIVATE
            ssl
            crypto
            z
        )
    endif()
endif()

# 复制MySQL DLL到输出目录（仅Windows且动态链接）
if(WIN32 AND NOT MYSQL_STATIC)
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
        # 可能的DLL文件名
        set(POSSIBLE_DLL_NAMES
            "mysqlcppconn9.dll"
            "mysqlcppconn8.dll"
            "mysqlcppconn.dll"
            "libmysqlcppconn9.dll"
            "libmysqlcppconn8.dll"
            "libmysqlcppconn.dll"
        )
        
        set(DLL_COPIED FALSE)
        foreach(dll_name IN LISTS POSSIBLE_DLL_NAMES)
            set(dll_path "${MYSQL_BIN_DIR}/${dll_name}")
            if(EXISTS "${dll_path}")
                add_custom_command(TARGET Bejeweled_Server POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${dll_path}"
                    $<TARGET_FILE_DIR:Bejeweled_Server>
                    COMMENT "Copying ${dll_name}"
                )
                message(STATUS "Will copy ${dll_name} to output directory")
                set(DLL_COPIED TRUE)
                break()
            endif()
        endforeach()
      
        # 复制其他可能的依赖DLL
        file(GLOB MYSQL_DLLS "${MYSQL_BIN_DIR}/*.dll")
        foreach(dll_file IN LISTS MYSQL_DLLS)
            get_filename_component(dll_name_only "${dll_file}" NAME)
            # 避免重复复制主要的conn DLL
            if(NOT DLL_COPIED OR NOT "${dll_name_only}" IN_LIST POSSIBLE_DLL_NAMES)
                add_custom_command(TARGET Bejeweled_Server POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${dll_file}"
                    $<TARGET_FILE_DIR:Bejeweled_Server>
                    COMMENT "Copying ${dll_name_only}"
                )
            endif()
        endforeach()
    endif()
endif()

# Windows网络库
if(WIN32)
    target_link_libraries(Bejeweled_Server PRIVATE ws2_32 mswsock)
endif()

# 打印配置摘要
message(STATUS "========================================")
message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Boost found: ${Boost_FOUND}")
message(STATUS "MySQL found: ${MySQL_FOUND}")
if(MySQL_FOUND)
    message(STATUS "MySQL include dir: ${MySQL_INCLUDE_DIRS}")
    message(STATUS "MySQL library: ${MySQL_LIBRARIES}")
    message(STATUS "MySQL static: ${MYSQL_STATIC}")
endif()
message(STATUS "========================================")