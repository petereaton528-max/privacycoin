// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 petereaton528-max
#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
namespace pc_rules {
// Logical consensus rules are distinct from transaction serialization, proof
// identifiers, P2P wire versions and encrypted wallet/storage envelope versions.
struct Rules { uint8_t consensus,block,transaction,proof; };
inline constexpr Rules v1{1,18,2,6}; // RCTTypeBulletproofPlus (CLSAG authorization)
#ifdef PC_OFFLINE_MOCK_UPGRADE
#ifndef PC_OFFLINE_CREATOR_VESTING
#error Mock upgrade requires the isolated candidate build
#endif
#ifdef PC_OFFLINE_ACCELERATED_VESTING
#error Do not combine unrelated mock policies
#endif
// Bound into creator_draft::domain and therefore the validated Genesis extra.
// No production activation, clock, RPC, remote configuration or voting switch.
inline constexpr uint64_t activation=84;
inline constexpr Rules v2{2,19,2,6};
inline std::string commitment() {
  auto encode=[](Rules r){return std::to_string(r.consensus)+":"+std::to_string(r.block)+":"+std::to_string(r.transaction)+":"+std::to_string(r.proof);};
  return "|rules="+encode(v1)+"|activate="+std::to_string(activation)+"|rules="+encode(v2);
}
#else
inline constexpr uint64_t activation=0; // No scheduled production/Devnet upgrade.
#endif
inline Rules at(uint64_t height) {
  if(activation && height>=activation) {
#ifdef PC_OFFLINE_MOCK_UNAWARE
    return v1; // Negative fixture: emulate an old validator unaware of activation.
#elif defined(PC_OFFLINE_MOCK_V1_ONLY)
    throw std::runtime_error("unsupported activated consensus rules");
#else
#ifdef PC_OFFLINE_MOCK_UPGRADE
    return v2;
#else
    throw std::runtime_error("no configured consensus activation");
#endif
#endif
  }
  return v1;
}
inline std::string transaction_domain(const std::string& base,uint64_t height) {
  return at(height).consensus==1?base:base+"/rules/2";
}
}
