add_executable(privacycoin-wallet-crypto "${CMAKE_CURRENT_LIST_DIR}/../../src/wallet/crypto.cpp")
set_target_properties(privacycoin-wallet-crypto PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/phase2")
target_include_directories(privacycoin-wallet-crypto PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(privacycoin-wallet-crypto PRIVATE cryptonote_basic ringct sodium)
