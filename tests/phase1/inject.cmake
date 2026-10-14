# Reuse the frozen Phase 0 targets without editing them or their evidence.
include("${CMAKE_CURRENT_LIST_DIR}/../phase0/inject.cmake")
function(privacycoin_phase1_targets)
  include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/linux-fixture.cmake")
  include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/CMakeLists.txt")
endfunction()
cmake_language(DEFER CALL privacycoin_phase1_targets)
