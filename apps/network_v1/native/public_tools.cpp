// Private stdin/stdout adapter for the pinned, unmodified upstream primitives.
// Never run with shell tracing or record its streams as evidence.
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "consensus/development_profile.h"
#include "randomx.h"
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
extern "C" {
#include "crypto/crypto-ops.h"
}
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "ringct/rctOps.h"
#include <sodium.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <chrono>

template<class T> std::string hex(const T& v) {
  static const char h[]="0123456789abcdef"; std::string s;
  const auto* p=reinterpret_cast<const unsigned char*>(&v);
  for(size_t i=0;i<sizeof(T);++i){s+=h[p[i]>>4];s+=h[p[i]&15];} return s;
}
template<class T> T read(std::istream& in) {
  std::string s; in>>s; if(s.size()!=sizeof(T)*2) throw std::runtime_error("length");
  T v{}; auto* p=reinterpret_cast<unsigned char*>(&v);
  auto digit=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;throw std::runtime_error("hex");};
  for(size_t i=0;i<sizeof(T);++i) p[i]=(digit(s[2*i])<<4)|digit(s[2*i+1]);
  return v;
}
void point(const crypto::public_key& p) {
  if(crypto_core_ed25519_is_valid_point(reinterpret_cast<const unsigned char*>(&p))!=1)throw std::runtime_error("point");
}
void scalar(const crypto::secret_key& s) {
  crypto::public_key p; if(!crypto::secret_key_to_public_key(s,p))throw std::runtime_error("scalar");point(p);
}
uint32_t index(std::istream& in) { uint64_t i; if(!(in>>i)||i>10000)throw std::runtime_error("index");return uint32_t(i); }
crypto::hash claim_message(std::istream& in) {
  auto block=read<crypto::hash>(in);std::string alias;in>>alias;
  if(alias.empty()||alias.size()>48||alias.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")!=std::string::npos)throw std::runtime_error("alias");
  std::string m="PrivacyCoinDev01/leaderboard-ownership/v1/a0d9ba16f1f6b2fb2f480197ff9dec17468db0d5e6df9cfcb4b2b2a91ecffc87/";
  m+=hex(block)+"/"+alias;return crypto::cn_fast_hash(m.data(),m.size());
}
int main() {
  try {
    if(sodium_init()<0)throw std::runtime_error("entropy");
    std::string line; if(!std::getline(std::cin,line)||line.size()>700000)throw std::runtime_error("request");
    std::istringstream in(line);std::string op;in>>op;
    if(op=="derive") {
      auto seed=read<crypto::hash>(in); std::string material="PrivacyCoin/devnet/wallet/v1/"; material.append(reinterpret_cast<const char*>(&seed),32);
      crypto::secret_key b,a;crypto::public_key B,A;
      crypto::hash_to_scalar(material.data(),material.size(),b); scalar(b);
      crypto::hash_to_scalar(&b,sizeof(b),a);scalar(a);
      crypto::secret_key_to_public_key(b,B);crypto::secret_key_to_public_key(a,A);
      std::cout<<hex(b)<<' '<<hex(a)<<' '<<hex(B)<<' '<<hex(A);
      sodium_memzero(&seed,sizeof(seed));sodium_memzero(material.data(),material.size());
    } else if(op=="address") {
      cryptonote::account_keys keys{};keys.m_view_secret_key=read<crypto::secret_key>(in);scalar(keys.m_view_secret_key);
      keys.m_account_address.m_spend_public_key=read<crypto::public_key>(in);point(keys.m_account_address.m_spend_public_key);
      crypto::secret_key_to_public_key(keys.m_view_secret_key,keys.m_account_address.m_view_public_key);
      auto n=index(in);auto address=hw::get_device("default").get_subaddress(keys,{0,n});
      std::cout<<hex(address.m_spend_public_key)<<' '<<hex(address.m_view_public_key);
    } else if(op=="output") {
      auto D=read<crypto::public_key>(in),C=read<crypto::public_key>(in);point(D);point(C);
      auto sub=index(in),n=index(in);if(sub>1)throw std::runtime_error("kind");
      crypto::public_key R,P;crypto::secret_key r;crypto::generate_keys(R,r);
      if(sub)R=rct::rct2pk(rct::scalarmultKey(rct::pk2rct(D),rct::sk2rct(r)));
      crypto::key_derivation deriv;
      if(!crypto::generate_key_derivation(C,r,deriv)||!crypto::derive_public_key(deriv,n,D,P))throw std::runtime_error("derive");
      std::cout<<hex(R)<<' '<<hex(P);
    } else if(op=="scan"||op=="prove"||op=="claim") {
      cryptonote::account_keys keys{};keys.m_view_secret_key=read<crypto::secret_key>(in);scalar(keys.m_view_secret_key);
      keys.m_account_address.m_spend_public_key=read<crypto::public_key>(in);point(keys.m_account_address.m_spend_public_key);
      crypto::secret_key_to_public_key(keys.m_view_secret_key,keys.m_account_address.m_view_public_key);
      auto count=index(in);if(!count)throw std::runtime_error("range");
      auto R=read<crypto::public_key>(in),P=read<crypto::public_key>(in);point(R);point(P);auto n=index(in);
      crypto::key_derivation deriv;if(!crypto::generate_key_derivation(R,keys.m_view_secret_key,deriv))throw std::runtime_error("derive");
      int found=-1;for(uint32_t i=0;i<count;++i){auto address=hw::get_device("default").get_subaddress(keys,{0,i});crypto::public_key expected;
        if(!crypto::derive_public_key(deriv,n,address.m_spend_public_key,expected))throw std::runtime_error("derive");
        if(expected==P){found=i;break;}}
      if(op=="scan")std::cout<<found;
      else {
        if(found<0)throw std::runtime_error("not owned");
        auto b=read<crypto::secret_key>(in);scalar(b);crypto::public_key B;crypto::secret_key_to_public_key(b,B);
        if(B!=keys.m_account_address.m_spend_public_key)throw std::runtime_error("authority");
        if(found){auto m=hw::get_device("default").get_subaddress_secret_key(keys.m_view_secret_key,{0,uint32_t(found)});sc_add(reinterpret_cast<unsigned char*>(&b),reinterpret_cast<const unsigned char*>(&b),reinterpret_cast<const unsigned char*>(&m));}
        crypto::secret_key x;crypto::derive_secret_key(deriv,n,b,x);crypto::public_key X;crypto::secret_key_to_public_key(x,X);
        if(X!=P)throw std::runtime_error("authority");
        constexpr char domain[]="PrivacyCoin/Phase2/ownership-proof-only";
        const auto challenge=op=="claim"?claim_message(in):crypto::cn_fast_hash(domain,sizeof(domain)-1);
        crypto::signature sig;crypto::generate_signature(challenge,P,x,sig);
        if(!crypto::check_signature(challenge,P,sig))throw std::runtime_error("signature");
        if(op=="claim")std::cout<<hex(sig);else std::cout<<"verified";
      }
    } else if(op=="mine-template"||op=="mine-template-stats") {
      std::string h;in>>h;if(h.size()>600000||h.size()%2)throw std::runtime_error("block");std::string raw;
      for(size_t i=0;i<h.size();i+=2){auto p=h.substr(i,2);if(p.find_first_not_of("0123456789abcdef")!=std::string::npos)throw std::runtime_error("hex");raw+=char(std::stoul(p,nullptr,16));}
      cryptonote::block b;if(!cryptonote::parse_and_validate_block_from_blob(raw,b))throw std::runtime_error("block");
      auto key=read<crypto::hash>(in);std::string target;in>>target;if(target.empty()||target.size()>39||target.find_first_not_of("0123456789")!=std::string::npos)throw std::runtime_error("difficulty");
      cryptonote::difficulty_type difficulty(target);if(!difficulty)throw std::runtime_error("difficulty");
      unsigned budget;in>>budget;if(!in||budget<1||budget>4096)throw std::runtime_error("budget");phase0::seed_height(0);
      auto cache=randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);if(!cache)throw std::runtime_error("cache");randomx_init_cache(cache,&key,sizeof(key));
      auto vm=randomx_create_vm(static_cast<randomx_flags>(randomx_get_flags()&RANDOMX_FLAG_JIT),cache,nullptr);if(!vm)throw std::runtime_error("vm");
      auto started=std::chrono::steady_clock::now();unsigned hashes=0;
      bool found=false;for(unsigned i=0;i<budget;++i){b.nonce=crypto::rand<uint32_t>();auto blob=cryptonote::get_block_hashing_blob(b);crypto::hash out;randomx_calculate_hash(vm,blob.data(),blob.size(),&out);++hashes;if(phase0::pow_valid(out,difficulty)){found=true;break;}}
      auto elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-started).count();
      randomx_destroy_vm(vm);randomx_release_cache(cache);
      std::string result="NOT_FOUND";
      if(found){result.clear();auto bytes=cryptonote::block_to_blob(b);for(unsigned char x:bytes){result+="0123456789abcdef"[x>>4];result+="0123456789abcdef"[x&15];}}
      if(op=="mine-template-stats")std::cout<<"{\"block\":\""<<result<<"\",\"hashes\":"<<hashes<<",\"elapsed_seconds\":"<<elapsed<<"}";
      else std::cout<<result;
    } else if(op=="verify-claim") {
      auto P=read<crypto::public_key>(in);point(P);auto challenge=claim_message(in);auto sig=read<crypto::signature>(in);
      if(!crypto::check_signature(challenge,P,sig))throw std::runtime_error("proof");std::cout<<"verified";
    } else if(op=="describe-block") {
      std::string h;in>>h;if(h.size()>600000||h.size()%2)throw std::runtime_error("block");std::string raw;
      for(size_t i=0;i<h.size();i+=2){auto p=h.substr(i,2);if(p.find_first_not_of("0123456789abcdef")!=std::string::npos)throw std::runtime_error("hex");raw+=char(std::stoul(p,nullptr,16));}
      cryptonote::block b;if(!cryptonote::parse_and_validate_block_from_blob(raw,b)||cryptonote::block_to_blob(b)!=raw)throw std::runtime_error("block");
      rapidjson::Document d;d.SetObject();auto& a=d.GetAllocator();
      auto str=[&](const char* k,const std::string& v){d.AddMember(rapidjson::Value(k,a),rapidjson::Value(v.c_str(),a),a);};
      str("hash",hex(cryptonote::get_block_hash(b)));str("parent",hex(b.prev_id));d.AddMember("timestamp",b.timestamp,a);
      d.AddMember("transaction_count",uint64_t(b.tx_hashes.size()),a);
      if(b.miner_tx.vout.size()==1&&b.miner_tx.vout[0].target.type()==typeid(cryptonote::txout_to_key)){
        str("output_key",hex(boost::get<cryptonote::txout_to_key>(b.miner_tx.vout[0].target).key));
        str("R",hex(cryptonote::get_tx_pub_key_from_extra(b.miner_tx.extra)));d.AddMember("reward",b.miner_tx.vout[0].amount,a);
      }
      rapidjson::StringBuffer buf;rapidjson::Writer<rapidjson::StringBuffer> writer(buf);d.Accept(writer);std::cout<<buf.GetString();
    } else if(op=="check") {auto P=read<crypto::public_key>(in);point(P);std::cout<<"valid";}
    else if(op=="hash") {std::string bytes;in>>bytes;if(bytes.size()>2048||bytes.size()%2)throw std::runtime_error("length");std::string raw;
      for(size_t i=0;i<bytes.size();i+=2){auto pair=bytes.substr(i,2);if(pair.find_first_not_of("0123456789abcdef")!=std::string::npos)throw std::runtime_error("hex");raw+=char(std::stoul(pair,nullptr,16));}std::cout<<hex(crypto::cn_fast_hash(raw.data(),raw.size()));}
    else throw std::runtime_error("operation");
    std::string extra;if(in>>extra)throw std::runtime_error("trailing");std::cout<<'\n';sodium_memzero(line.data(),line.size());return 0;
  } catch(...) {std::cerr<<"wallet crypto request rejected\n";return 1;}
}
