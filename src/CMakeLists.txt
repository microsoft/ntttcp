# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.15)

# Disable in-source builds to prevent source tree corruption.
if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()

# Set policies for more modern cmake
cmake_policy(SET CMP0091 NEW) # Runtime flags
cmake_policy(SET CMP0092 NEW) # Warning flags

project(ntttcp)

# Use static CRT
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(ntttcp ntttcp.c)

target_include_directories(ntttcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_options(ntttcp PUBLIC /WX /W3 /sdl /permissive- /guard:cf /Zi)

target_compile_definitions(ntttcp PUBLIC UNICODE _UNICODE)

target_link_libraries(ntttcp PUBLIC ws2_32 iphlpapi)

target_link_options(ntttcp PUBLIC /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG:FULL)
