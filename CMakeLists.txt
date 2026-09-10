cmake_minimum_required(VERSION 3.20)
project(ogxbox_cpp CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- third-party -------------------------------------------------------------
set(FMT_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/fmt EXCLUDE_FROM_ALL)

add_library(tomlplusplus INTERFACE)
target_include_directories(tomlplusplus INTERFACE third_party/tomlplusplus/include)

add_library(inja INTERFACE)
target_include_directories(inja INTERFACE
  third_party/inja/include
  third_party/inja/third_party/include)   # bundled nlohmann/json

add_library(spdlog INTERFACE)
target_include_directories(spdlog INTERFACE third_party/spdlog/include)
target_compile_definitions(spdlog INTERFACE SPDLOG_FMT_EXTERNAL SPDLOG_HEADER_ONLY)

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/zydis EXCLUDE_FROM_ALL)

# --- reused ReXGlue codegen (ISA-neutral subset) ---------------------------
add_library(rexcodegen STATIC
  vendor/rexglue/src/codegen/function_graph.cpp
  vendor/rexglue/src/codegen/vtable_scanner.cpp
  vendor/rexglue/src/codegen/sig_scanner.cpp
  vendor/rexglue/src/codegen/config.cpp
  vendor/rexglue/src/codegen/codegen_flags.cpp
)
target_include_directories(rexcodegen PUBLIC
  vendor/rexglue/include
  vendor/rexglue/src
  vendor/rexglue/src/codegen
  src
)
target_link_libraries(rexcodegen PUBLIC
  fmt::fmt tomlplusplus inja spdlog Zydis
)

if (MSVC)
  target_compile_options(rexcodegen PRIVATE /W1 /wd4244 /wd4267 /EHsc)
  target_compile_definitions(rexcodegen PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()
