// Private stdin/stdout adapter for the pinned, unmodified upstream primitives.
// Never run with shell tracing or record its streams as evidence.
#include "crypto/crypto.h"
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
int main() {
  try {
    if(sodium_init()<0)throw std::runtime_error("entropy");
    std::string line; if(!std::getline(std::cin,line)||line.size()>8192)throw std::runtime_error("request");
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
    } else if(op=="scan"||op=="prove") {
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
        const auto challenge=crypto::cn_fast_hash(domain,sizeof(domain)-1);
        crypto::signature sig;crypto::generate_signature(challenge,P,x,sig);
        if(!crypto::check_signature(challenge,P,sig))throw std::runtime_error("signature");
        std::cout<<"verified";
      }
    } else if(op=="check") {auto P=read<crypto::public_key>(in);point(P);std::cout<<"valid";}
    else if(op=="hash") {std::string bytes;in>>bytes;if(bytes.size()>2048||bytes.size()%2)throw std::runtime_error("length");std::string raw;
      for(size_t i=0;i<bytes.size();i+=2){auto pair=bytes.substr(i,2);if(pair.find_first_not_of("0123456789abcdef")!=std::string::npos)throw std::runtime_error("hex");raw+=char(std::stoul(pair,nullptr,16));}std::cout<<hex(crypto::cn_fast_hash(raw.data(),raw.size()));}
    else throw std::runtime_error("operation");
    std::string extra;if(in>>extra)throw std::runtime_error("trailing");std::cout<<'\n';sodium_memzero(line.data(),line.size());return 0;
  } catch(...) {std::cerr<<"wallet crypto request rejected\n";return 1;}
}
