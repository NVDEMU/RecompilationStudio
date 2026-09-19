# Native test-runtime for the cycle micro-benchmark ROM (ruler #2).
cmake_minimum_required(VERSION 3.20)
project(CycleTestROM C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

# The psxrecomp worktree root is two levels up (tools/cycle_testrom -> worktree).
set(PSXRECOMP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH
    "Path to psxrecomp")

include("${PSXRECOMP_ROOT}/runtime/runtime.cmake")

file(GLOB GAME_GENERATED_UNITS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/cycle_testrom.exe_cu_*.c")
list(SORT GAME_GENERATED_UNITS)
set(GAME_GENERATED_DISPATCH
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/cycle_testrom.exe_dispatch.c")

psxrecomp_add_runtime_target(psx-cyctest
    GAME_GENERATED_UNITS ${GAME_GENERATED_UNITS}
    GAME_GENERATED_DISPATCH_C "${GAME_GENERATED_DISPATCH}"
    DEBUG_PORT 4600
    WINDOW_TITLE "Cycle Test ROM"
    DEFAULT_BIOS_PATH "${PSXRECOMP_ROOT}/bios/SCPH1001.BIN"
    DEFAULT_GAME_CONFIG_PATH "game.toml"
)
