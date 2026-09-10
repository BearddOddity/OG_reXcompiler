cmake_minimum_required(VERSION 3.20)
project(ogxbox_cpp C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
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

add_library(tomlc99 STATIC third_party/tomlc99/toml.c)
target_include_directories(tomlc99 PUBLIC third_party/tomlc99)
if (MSVC)
  target_compile_definitions(tomlc99 PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# --- reused ReXGlue codegen core (ISA-neutral subset) ----------------------
# ReXGlue's own graph model + RTTI/sig scanners + TOML config, compiled against
# a Zydis-backed x86::Instruction. This is the bridge object the Part 2 runtime
# integration builds on; Part 1's analysis + emit is the proven port below.
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
)
target_link_libraries(rexcodegen PUBLIC
  fmt::fmt tomlplusplus inja spdlog Zydis
)
if (MSVC)
  target_compile_options(rexcodegen PRIVATE /W1 /wd4244 /wd4267 /EHsc)
  target_compile_definitions(rexcodegen PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

# --- ogxbox: the x86 recompiler (ported from the `c` branch) ---------------
# Complete analysis + C emitter + XBE loader + config. Compile- and
# boot-verified on the `c` branch; brought here so the `cpp` branch has a
# working Part 1 without re-deriving 8k lines of PPC-shaped scanner/phase/emit
# code that this project already solved for x86.
add_executable(ogxbox
  src/main.c
  src/xbe.c
  src/kernel_exports.c
  src/binary_view.c
  src/decoded.c
  src/func_graph.c
  src/scanners.c
  src/func_scanner.c
  src/config.c
  src/phases.c
  src/context.c
  src/emit_operand.c
  src/emit.c
  src/writers.c
)
target_include_directories(ogxbox PRIVATE src)
target_link_libraries(ogxbox PRIVATE Zydis tomlc99)
target_compile_definitions(ogxbox PRIVATE OGX_RUNTIME_DIR="${CMAKE_CURRENT_SOURCE_DIR}/runtime")
if (MSVC)
  target_compile_definitions(ogxbox PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
