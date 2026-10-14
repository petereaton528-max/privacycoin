// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 petereaton528-max
// Offline candidate only. Never an approved Mainnet profile.
#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include "crypto/hash.h"
#include "consensus/rule_versions.h"
namespace creator_draft {
inline constexpr uint64_t total=159627169409884823ULL;
inline constexpr uint64_t liquid=total/10;
inline constexpr uint64_t locked=total-liquid;
#ifdef PC_BOUND_DOMAIN
#if !defined(PC_OFFLINE_CREATOR_VESTING) || defined(PC_OFFLINE_ACCELERATED_VESTING) || defined(PC_OFFLINE_MOCK_UPGRADE)
#error Bound policy must use the exact unaccelerated V1 allocation rules
#endif
inline constexpr uint64_t interval=65700;
inline constexpr char domain[]=PC_BOUND_DOMAIN;
#elif defined(PC_OFFLINE_ACCELERATED_VESTING)
#ifndef PC_OFFLINE_CREATOR_VESTING
#error Accelerated vesting requires offline-only build
#endif
inline constexpr uint64_t interval=80;
inline constexpr char domain[]="PrivacyCoin/ACCELERATED-NON-ECONOMIC-VESTING/v1";
#else
inline constexpr uint64_t interval=65700;
#ifdef PC_OFFLINE_MOCK_UPGRADE
inline constexpr char domain[]="PrivacyCoin/MOCK-UPGRADE-AT-84-NON-ECONOMIC/v1";
#else
inline constexpr char domain[]="PrivacyCoin/UNAPPROVED-CREATOR-VESTING-DRAFT/v1";
#endif
#endif
inline constexpr uint64_t releases=16, window=interval*releases;
#ifdef PC_BOUND_NETWORK
inline constexpr char network[]=PC_BOUND_NETWORK;
#else
inline constexpr char network[]="PrivacyCoinLab01";
#endif
static_assert(sizeof(network)==17,"Native P2P magic requires exactly 16 bytes plus terminator");
inline uint64_t amount(size_t i){
  if(i>releases)throw std::invalid_argument("draft tranche index");
  // Remainder goes to earliest releases, one atomic unit each.
  return i==0?liquid:locked/releases+(i<=locked%releases?1:0);
}
inline uint64_t unlock(size_t i){
  if(i>releases)throw std::invalid_argument("draft tranche index");
  return uint64_t(i)*interval;
}
inline std::string policy_text(){
  std::string text=std::string(domain)+"|"+std::to_string(total);
  for(size_t i=0;i<=releases;++i)text+="|"+std::to_string(i)+":"+std::to_string(unlock(i))+":"+std::to_string(amount(i));
#ifdef PC_OFFLINE_MOCK_UPGRADE
  text+=pc_rules::commitment();
#endif
  return text;
}
inline std::string genesis_extra(){
  auto text=policy_text();auto hash=crypto::cn_fast_hash(text.data(),text.size());
  const auto* bytes=reinterpret_cast<const unsigned char*>(&hash);const char* digits="0123456789abcdef";
  std::string value=std::string(domain)+"/policy/";
  for(size_t i=0;i<sizeof(hash);++i){value+=digits[bytes[i]>>4];value+=digits[bytes[i]&15];}
  return value;
}
}
