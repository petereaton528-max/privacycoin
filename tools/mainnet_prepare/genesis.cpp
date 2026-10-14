// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 petereaton528-max
// Offline draft only. No sockets, database, wallet, mining or launch entrypoint.
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include <iostream>
#include <stdexcept>
template<class T> std::string hex(const T& value) {
  const char* digits="0123456789abcdef";std::string out;
  for(unsigned char byte: value){out+=digits[byte>>4];out+=digits[byte&15];}return out;
}
int main(){
  try{
    std::string digest,extra;if(!std::getline(std::cin,digest)||digest.size()!=64||digest.find_first_not_of("0123456789abcdef")!=std::string::npos)throw std::runtime_error("draft digest");
    if(std::getline(std::cin,extra))throw std::runtime_error("trailing input");
    cryptonote::block block{};block.major_version=16;block.minor_version=0;block.timestamp=0;block.nonce=0;
    block.miner_tx.version=1;block.miner_tx.unlock_time=0;block.miner_tx.vin.push_back(cryptonote::txin_gen{0});
    if(!cryptonote::add_extra_nonce_to_tx_extra(block.miner_tx.extra,"PrivacyCoin/Mainnet-DRAFT/v1/"+digest))throw std::runtime_error("extra");
    auto raw=cryptonote::block_to_blob(block);cryptonote::block parsed;
    if(!cryptonote::parse_and_validate_block_from_blob(raw,parsed)||cryptonote::block_to_blob(parsed)!=raw)throw std::runtime_error("canonical parse");
    const auto hash=cryptonote::get_block_hash(parsed);std::string hashbytes(reinterpret_cast<const char*>(&hash),sizeof(hash));
    std::cout<<"{\"genesis_bytes\":\""<<hex(raw)<<"\",\"genesis_hash\":\""<<hex(hashbytes)<<"\",\"genesis_issuance_atomic\":0,\"native_canonical_roundtrip\":true}\n";
  }catch(...){std::cerr<<"DRAFT_GENESIS_REJECTED\n";return 1;}
}
