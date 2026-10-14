// Phase 0 development-profile adapter. No node/network or cryptographic primitive.
#pragma once
#include <algorithm>
#include <cstdlib>
#include <limits>
#include <stdexcept>
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "crypto/hash-ops.h"

namespace phase0 {
using wide = boost::multiprecision::uint256_t;
inline bool pow_valid(const crypto::hash& hash, cryptonote::difficulty_type d) {
  return d != 0 && cryptonote::check_hash(hash, d);
}
inline cryptonote::difficulty_type difficulty(std::vector<uint64_t> time,
    std::vector<cryptonote::difficulty_type> work) {
  if (time.size() != work.size()) throw std::invalid_argument("history lengths");
  // Caller supplies latest <=735 chronological samples, excluding genesis.
  if (time.size() > 735) throw std::invalid_argument("history too long");
  for (size_t i = 1; i < work.size(); ++i)
    if (work[i] <= work[i-1]) throw std::invalid_argument("non-increasing work");
  auto d = cryptonote::next_difficulty(time, work, 120);
  if (d == 0) throw std::overflow_error("difficulty overflow");
  return d;
}
inline uint64_t subsidy(const wide& issued) {
  uint64_t reward = 0;
  const auto maximum = std::numeric_limits<uint64_t>::max();
  auto capped = issued >= wide(maximum) ? maximum : issued.convert_to<uint64_t>();
  if (!cryptonote::get_block_reward(300000, 300000, capped, reward, 16))
    throw std::runtime_error("upstream reward rejected");
  return reward;
}
inline uint64_t payout(const wide& issued, const wide& fees) {
  const auto reward = subsidy(issued);
  if (fees > wide(std::numeric_limits<uint64_t>::max() - reward))
    throw std::overflow_error("coinbase payout");
  return reward + fees.convert_to<uint64_t>();
}
inline wide add_issuance(const wide& issued, uint64_t reward) {
  if (issued > std::numeric_limits<wide>::max() - reward)
    throw std::overflow_error("issued supply");
  return issued + reward;
}
inline bool mature(uint64_t created, uint64_t candidate) {
  return candidate >= created && candidate - created >= 60;
}
inline wide add_work(const wide& parent, cryptonote::difficulty_type d) {
  if (d == 0 || parent > std::numeric_limits<wide>::max() - wide(d))
    throw std::overflow_error("chain work");
  return parent + d;
}
inline bool replaces(const wide& candidate, const wide& current) { return candidate > current; }
inline uint64_t seed_height(uint64_t h) {
  // A local environment must never change consensus. Fail before upstream's cache.
  if (std::getenv("SEEDHASH_EPOCH_BLOCKS") || std::getenv("SEEDHASH_EPOCH_LAG"))
    throw std::invalid_argument("consensus-affecting environment override");
  return crypto::rx_seedheight(h);
}
}
