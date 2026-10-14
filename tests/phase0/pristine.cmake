# Build portability only: no source edits, companion target or protocol adapter.
# GCC 16 needs an explicit thread header in these two upstream test TUs.
function(pristine_thread_headers)
  if(TARGET unit_tests AND MINGW)
    foreach(test_source epee_boosted_tcp_server.cpp node_server.cpp)
      set_property(SOURCE "${CMAKE_SOURCE_DIR}/tests/unit_tests/${test_source}"
        TARGET_DIRECTORY unit_tests APPEND PROPERTY COMPILE_OPTIONS -include thread)
    endforeach()
  endif()
endfunction()
cmake_language(DEFER CALL pristine_thread_headers)
