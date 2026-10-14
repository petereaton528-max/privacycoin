add_executable(privacycoin-devnet
  "${CMAKE_CURRENT_LIST_DIR}/../../src/devnet/ledger.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/../../src/devnet/node.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/unit.cpp")
set_target_properties(privacycoin-devnet PROPERTIES
  CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/phase1")
target_include_directories(privacycoin-devnet PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../../src"
  "${CMAKE_SOURCE_DIR}/src" "${CMAKE_SOURCE_DIR}/external/randomx/src"
  "${CMAKE_SOURCE_DIR}/external/db_drivers/liblmdb")
target_link_libraries(privacycoin-devnet PRIVATE cryptonote_basic ringct randomx lmdb)
if(WIN32)
  target_link_libraries(privacycoin-devnet PRIVATE ws2_32)
endif()
