cmake_minimum_required(VERSION 3.16)
project(ogxbox C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --- third-party -----------------------------------------------------------
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/zydis)

add_library(tomlc99 STATIC third_party/tomlc99/toml.c)
target_include_directories(tomlc99 PUBLIC third_party/tomlc99)

# --- the recompiler ------------------------------------------------------
add_executable(ogxbox
  src/main.c
  src/xbe.c
  src/kernel_exports.c
  src/binary_view.c
  src/decoded.c
  src/func_graph.c
  # src/scanners.c
  # src/func_scanner.c
  # src/config.c
  # src/phases.c
  # src/emit_operand.c
  # src/emit.c
  # src/codegen_writer.c
  # src/image_writer.c
  # src/graph_export.c
)
target_include_directories(ogxbox PRIVATE src)
target_link_libraries(ogxbox PRIVATE Zydis tomlc99)

if (MSVC)
  target_compile_definitions(ogxbox PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
