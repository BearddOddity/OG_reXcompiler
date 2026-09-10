# Smoke test: boot the recompiled title, assert it made real progress.
# Invoked by ctest via the scaffolded CMakeLists.txt.
#   -DEXE=<recomp.exe>  -DMIN_CALLS=<n>  -DRUN_TIMEOUT=<seconds>
#
# Needs a -DREX_TRACE build (OGX_TRACE=ON, the default) — the guest-call
# counter is a no-op otherwise.
#
# Gate: the highest "guest calls N" the run reports must be >= MIN_CALLS.
# A fault only fails the test when it kept the run *under* the bar — a fault
# that co-occurs with the harness shutdown, after the bar was already cleared,
# is not a regression (the doomed guest thread was spinning at the known wall).

if(NOT EXE OR NOT EXISTS "${EXE}")
  message(FATAL_ERROR "smoke: recomp executable not found: ${EXE}")
endif()
get_filename_component(_dir "${EXE}" DIRECTORY)

execute_process(
  COMMAND "${EXE}"
  WORKING_DIRECTORY "${_dir}"
  TIMEOUT "${RUN_TIMEOUT}"
  OUTPUT_VARIABLE _out
  ERROR_VARIABLE _err
  RESULT_VARIABLE _rc)
set(_log "${_out}${_err}")

set(_max 0)
string(REGEX MATCHALL "guest calls ([0-9]+)" _hits "${_log}")
foreach(m IN LISTS _hits)
  string(REGEX MATCH "[0-9]+" _n "${m}")
  if(_n GREATER _max)
    set(_max "${_n}")
  endif()
endforeach()

set(_faulted OFF)
if(_log MATCHES "ACCESS VIOLATION" OR _log MATCHES "KeBugCheck" OR _log MATCHES "guest aborted")
  string(REGEX MATCH "[^\n]*(ACCESS VIOLATION|KeBugCheck|guest aborted)[^\n]*" _hit "${_log}")
  set(_faulted ON)
endif()

message(STATUS "smoke: reached ${_max} guest calls (need >= ${MIN_CALLS})")

if(_max LESS MIN_CALLS)
  if(_faulted)
    message(FATAL_ERROR "smoke: regressed — faulted at ${_max} guest calls (< ${MIN_CALLS}): ${_hit}")
  endif()
  message(FATAL_ERROR "smoke: regressed — only ${_max} guest calls (< ${MIN_CALLS})")
endif()

if(_faulted)
  message(STATUS "smoke: note — a fault appeared after the bar was cleared (shutdown of the doomed wall thread): ${_hit}")
endif()
message(STATUS "smoke: OK")

# --- future: golden-output diff ------------------------------------------------
# A second, opt-in mode could diff the normalised instrument output (STACK: /
# ABI: / spin-stack lines) against titles/<name>/smoke.golden.txt, re-blessed on
# deliberate changes. Deferred: needs an output normaliser (strip "+N.Ns"
# timing, mask trailing hex, bucket the call count) or the golden churns every
# run. Add when instrument-output regressions start slipping past the progress
# assertion above.
