# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.24)

project(passmcp_sdk VERSION 0.0.10 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_library(passmcp_sdk STATIC
  src/sha2.cpp
  src/json.cpp
  src/attestation.cpp
  src/catalog.cpp
  src/server.cpp
  src/client.cpp
  src/stdio.cpp
  src/oauth.cpp
  src/http.cpp
)
add_library(passmcp::sdk ALIAS passmcp_sdk)

target_include_directories(passmcp_sdk
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

add_executable(quickstart examples/quickstart.cpp)
target_link_libraries(quickstart PRIVATE passmcp::sdk)
target_compile_definitions(quickstart PRIVATE
  PASSMCP_DEFAULT_STATEMENT_PATH="${CMAKE_CURRENT_SOURCE_DIR}/testdata/statement.json"
)

add_executable(stdio_server examples/stdio_server.cpp)
target_link_libraries(stdio_server PRIVATE passmcp::sdk)

enable_testing()

add_executable(sdk_test tests/sdk_test.cpp)
target_link_libraries(sdk_test PRIVATE passmcp::sdk)
target_compile_definitions(sdk_test PRIVATE
  PASSMCP_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/testdata"
)

add_executable(phase2_test tests/phase2_test.cpp)
target_link_libraries(phase2_test PRIVATE passmcp::sdk)
add_dependencies(phase2_test stdio_server)
target_compile_definitions(phase2_test PRIVATE
  PASSMCP_STDIO_SERVER_BIN="$<TARGET_FILE:stdio_server>"
)

add_test(NAME passmcp_sdk_test COMMAND sdk_test)
add_test(NAME passmcp_phase2_test COMMAND phase2_test)

include(GNUInstallDirs)
install(TARGETS passmcp_sdk
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/passmcp
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
