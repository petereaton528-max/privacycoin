# Attach evidence targets to the mature upstream build without patching it.
function(privacycoin_phase0_targets)
  # GCC 16 no longer supplies <thread> indirectly to this upstream test file.
  # Explicit forced includes affect only these test translation units, not consensus.
  if(TARGET unit_tests AND MINGW)
    foreach(test_source epee_boosted_tcp_server.cpp node_server.cpp)
      set_property(SOURCE "${CMAKE_SOURCE_DIR}/tests/unit_tests/${test_source}"
        TARGET_DIRECTORY unit_tests APPEND PROPERTY COMPILE_OPTIONS -include thread)
    endforeach()
  endif()
  include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/CMakeLists.txt")
endfunction()
cmake_language(DEFER CALL privacycoin_phase0_targets)
