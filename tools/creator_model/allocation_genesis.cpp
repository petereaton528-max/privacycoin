// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 petereaton528-max
// Public synthetic recipient only; draft serialized block, never an active genesis.
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "ringct/rctOps.h"
#include <iostream>
#include <sstream>
template<class T>std::string hx(const T& value){const char* d="0123456789abcdef";std::string out;for(unsigned char c:value){out+=d[c>>4];out+=d[c&15];}return out;}
crypto::public_key point(const std::string& text){
  if(text.size()!=64||text.find_first_not_of("0123456789abcdef")!=std::string::npos)throw std::runtime_error("point encoding");
  crypto::public_key p{};auto bytes=reinterpret_cast<unsigned char*>(&p);
  for(size_t i=0;i<32;++i)bytes[i]=std::stoul(text.substr(i*2,2),nullptr,16);
  if(!crypto::check_key(p)||!rct::isInMainSubgroup(rct::pk2rct(p))||p==crypto::null_pkey||rct::pk2rct(p)==rct::identity())throw std::runtime_error("point");return p;
}
int main(){try{
  char input[512];if(!std::cin.getline(input,sizeof(input)))throw std::runtime_error("bounded input");std::string rest;if(std::getline(std::cin,rest))throw std::runtime_error("trailing input");
  std::istringstream in(input);std::string amount,digest,P,R,extra;in>>amount>>digest>>P>>R;
  if(in>>extra||amount.empty()||amount.size()>20||amount.find_first_not_of("0123456789")!=std::string::npos||digest.size()!=64||digest.find_first_not_of("0123456789abcdef")!=std::string::npos)throw std::runtime_error("draft fields");
  auto allocation=std::stoull(amount);if(!allocation||std::to_string(allocation)!=amount)throw std::runtime_error("allocation");
  cryptonote::block b{};b.major_version=16;b.minor_version=0;b.timestamp=0;b.nonce=0;
  b.miner_tx.version=2;b.miner_tx.unlock_time=60;b.miner_tx.vin.push_back(cryptonote::txin_gen{0});
  b.miner_tx.vout.push_back(cryptonote::tx_out{allocation,cryptonote::txout_to_key{point(P)}});
  cryptonote::add_tx_pub_key_to_extra(b.miner_tx,point(R));
  if(!cryptonote::add_extra_nonce_to_tx_extra(b.miner_tx.extra,"PrivacyCoin/CREATOR-DRAFT/v1/"+digest))throw std::runtime_error("extra");
  auto raw=cryptonote::block_to_blob(b);cryptonote::block parsed;
  if(!cryptonote::parse_and_validate_block_from_blob(raw,parsed)||cryptonote::block_to_blob(parsed)!=raw||parsed.miner_tx.vout.size()!=1||parsed.miner_tx.vout[0].amount!=allocation)throw std::runtime_error("canonical draft");
  auto hash=cryptonote::get_block_hash(parsed);std::string hashbytes(reinterpret_cast<const char*>(&hash),sizeof(hash));
  std::cout<<"{\"genesis_bytes\":\""<<hx(raw)<<"\",\"coinbase_bytes\":\""<<hx(cryptonote::tx_to_blob(parsed.miner_tx))<<"\",\"genesis_hash\":\""<<hx(hashbytes)<<"\",\"creator_atomic\":"<<allocation<<",\"unlock_height\":60,\"native_canonical_roundtrip\":true,\"launchable\":false}\n";
}catch(...){std::cerr<<"CREATOR_DRAFT_REJECTED\n";return 1;}}
