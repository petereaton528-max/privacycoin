#include "ledger.h"
#include <cstring>
#include <iostream>
#include <limits>
#include "ringct/rctOps.h"

namespace pcdev {
static void need(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
std::string hex(const void* p, size_t n) {
  const auto* b = static_cast<const unsigned char*>(p);
  const char* digits = "0123456789abcdef";
  std::string s; s.reserve(n*2);
  for (size_t i=0; i<n; ++i) { s += digits[b[i]>>4]; s += digits[b[i]&15]; }
  return s;
}
std::string unhex(const std::string& s) {
  need(s.size()%2 == 0 && s.size() <= 600000, "hex size");
  auto digit=[](char c)->int { if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; throw std::runtime_error("noncanonical hex"); };
  std::string b; b.reserve(s.size()/2);
  for(size_t i=0;i<s.size();i+=2) b += char((digit(s[i])<<4)|digit(s[i+1]));
  return b;
}
uint64_t wall_time() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
crypto::public_key public_key(const std::string& s) {
  auto bytes=unhex(s); need(bytes.size()==32,"reward public key size");
  crypto::public_key p; std::memcpy(&p,bytes.data(),32);
  need(crypto::check_key(p),"invalid reward public key");
  // Pinned subgroup validation, including identity/small-order rejection.
  need(rct::isInMainSubgroup(rct::pk2rct(p)),"reward key subgroup");
  need(std::memcmp(&p,rct::identity().bytes,32)!=0,"identity reward public key");
  need(p != crypto::null_pkey,"zero reward public key");
  return p;
}
static void dbcheck(int rc) { if(rc) throw std::runtime_error(std::string("LMDB: ")+mdb_strerror(rc)); }
static std::string dbget(MDB_txn* t, MDB_dbi dbi, const std::string& k) {
  MDB_val key{k.size(),const_cast<char*>(k.data())}, value{};
  int rc=mdb_get(t,dbi,&key,&value);
  if(rc==MDB_NOTFOUND) return "";
  dbcheck(rc); return std::string(static_cast<char*>(value.mv_data),value.mv_size);
}
static void dbput(MDB_txn* t, MDB_dbi dbi, const std::string& k, const std::string& v) {
  MDB_val key{k.size(),const_cast<char*>(k.data())}, value{v.size(),const_cast<char*>(v.data())};
  dbcheck(mdb_put(t,dbi,&key,&value,0));
}
Ledger::Ledger(const std::string& directory) {
  phase0::seed_height(0); // Reject consensus-affecting RandomX environment overrides.
  Entry g; g.bytes=unhex(genesis_bytes);
  need(cryptonote::parse_and_validate_block_from_blob(g.bytes,g.block),"frozen genesis parse");
  need(cryptonote::block_to_blob(g.block)==g.bytes,"frozen genesis canonical bytes");
  g.id=hex(cryptonote::get_block_hash(g.block));
  need(g.id==genesis_id,"FROZEN GENESIS MUTATION");
  blocks.emplace(g.id,g); tip_id=g.id;
  cache=randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
  need(cache!=nullptr,"RandomX cache allocation");
  try {
    if(directory.empty()) return;
    std::filesystem::create_directories(directory);
    dbcheck(mdb_env_create(&db)); dbcheck(mdb_env_set_mapsize(db,1024ULL*1024*1024));
    dbcheck(mdb_env_open(db,directory.c_str(),MDB_NOTLS,0600));
    MDB_txn* t=nullptr; dbcheck(mdb_txn_begin(db,nullptr,0,&t));
    try {
      dbcheck(mdb_dbi_open(t,nullptr,0,&dbi));
      auto saved_identity=dbget(t,dbi,"identity");
      MDB_stat st{}; dbcheck(mdb_stat(t,dbi,&st));
      if(saved_identity.empty()) {
        need(st.ms_entries==0,"unidentified existing database refused");
        dbput(t,dbi,"identity",identity); dbput(t,dbi,"tip",tip_id);
      } else need(saved_identity==identity,"incompatible network/genesis/database profile");
      const auto saved_tip=dbget(t,dbi,"tip");
      std::vector<std::pair<std::string,std::string>> saved;
      MDB_cursor* cursor=nullptr; dbcheck(mdb_cursor_open(t,dbi,&cursor));
      MDB_val k{},v{}; int rc=mdb_cursor_get(cursor,&k,&v,MDB_FIRST);
      while(rc==0) {
        std::string key(static_cast<char*>(k.mv_data),k.mv_size);
        if(key.rfind("b:",0)==0) saved.emplace_back(key.substr(2),std::string(static_cast<char*>(v.mv_data),v.mv_size));
        else need(key=="identity"||key=="tip","unknown database record");
        rc=mdb_cursor_get(cursor,&k,&v,MDB_NEXT);
      }
      mdb_cursor_close(cursor); need(rc==MDB_NOTFOUND,"database cursor error");
      // Reconstruct topologically; persisted metadata is never trusted as consensus.
      while(!saved.empty()) {
        bool progress=false;
        for(auto i=saved.begin();i!=saved.end();) {
          cryptonote::block b;
          need(i->second.size()<=300000 && cryptonote::parse_and_validate_block_from_blob(i->second,b),"corrupt persisted block");
          if(blocks.count(hex(b.prev_id))) {
            auto e=validate(i->second,"",wall_time());
            need(e.id==i->first,"persisted block key mismatch");
            blocks.emplace(e.id,e); if(phase0::replaces(e.work,blocks.at(tip_id).work)) tip_id=e.id;
            i=saved.erase(i); progress=true;
          } else ++i;
        }
        need(progress,"orphan/corrupt persisted block graph");
      }
      need(blocks.count(saved_tip)&&blocks.at(saved_tip).work==blocks.at(tip_id).work,"corrupt persisted tip");
      tip_id=saved_tip;
      auto* committing=t; t=nullptr; dbcheck(mdb_txn_commit(committing));
    } catch(...) { if(t) mdb_txn_abort(t); throw; }
  } catch(...) {
    if(db) { mdb_env_close(db); db=nullptr; }
    if(vm) { randomx_destroy_vm(vm); vm=nullptr; }
    randomx_release_cache(cache); cache=nullptr; throw;
  }
}
Ledger::~Ledger() { if(vm) randomx_destroy_vm(vm); if(cache) randomx_release_cache(cache); if(db) mdb_env_close(db); }
Entry Ledger::tip() { std::lock_guard<std::recursive_mutex> lock(mutex); return blocks.at(tip_id); }
Entry Ledger::get(const std::string& id) { std::lock_guard<std::recursive_mutex> lock(mutex); return blocks.at(id); }
std::vector<Entry> Ledger::entries() {
  std::lock_guard<std::recursive_mutex> lock(mutex); std::vector<Entry> out;
  for(const auto& p:blocks) out.push_back(p.second);
  std::sort(out.begin(),out.end(),[](const Entry&a,const Entry&b){ return a.height==b.height ? a.id<b.id : a.height<b.height; });
  return out;
}
std::vector<std::string> Ledger::active_chain() {
  std::lock_guard<std::recursive_mutex> lock(mutex); std::vector<std::string> out;
  for(auto p=tip_id; !p.empty(); p=blocks.at(p).parent) out.push_back(p);
  std::reverse(out.begin(),out.end()); return out;
}
uint64_t Ledger::median(const Entry& p) {
  std::vector<uint64_t> t; auto e=p;
  while(e.height>0 && t.size()<60) { t.push_back(e.block.timestamp); e=blocks.at(e.parent); }
  if(t.empty()) return 0;
  return epee::misc_utils::median(t);
}
cryptonote::difficulty_type Ledger::next(const Entry& p) {
  std::vector<uint64_t> times;
  std::vector<phase0::wide> totals;
  std::vector<cryptonote::difficulty_type> work;
  auto e=p; phase0::wide max=std::numeric_limits<cryptonote::difficulty_type>::max();
  while(e.height>0 && times.size()<735) {
    times.push_back(e.block.timestamp); totals.push_back(e.work);
    e=blocks.at(e.parent);
  }
  std::reverse(times.begin(),times.end()); std::reverse(totals.begin(),totals.end());
  // DAA uses differences: remove a common offset before the 128-bit upstream API.
  // A wide lifetime work total must not silently truncate or limit chain lifetime.
  if(!totals.empty()) for(const auto& total:totals) {
    const auto relative=total-totals.front();
    need(relative<=max,"DAA window work exceeds upstream 128-bit range");
    work.push_back(relative.convert_to<cryptonote::difficulty_type>());
  }
  return phase0::difficulty(times,work);
}
crypto::hash Ledger::seed(const Entry& p, uint64_t h) {
  const auto target=phase0::seed_height(h); auto e=p;
  while(e.height>target) e=blocks.at(e.parent);
  need(e.height==target,"missing branch RandomX seed");
  return cryptonote::get_block_hash(e.block);
}
crypto::hash Ledger::hash(const cryptonote::block& b, const crypto::hash& key) {
  std::lock_guard<std::recursive_mutex> lock(mutex);
  if(!initialized||key!=cache_key) {
    if(vm) { randomx_destroy_vm(vm); vm=nullptr; }
    randomx_init_cache(cache,&key,sizeof(key));
    auto flags=static_cast<randomx_flags>(randomx_get_flags() & RANDOMX_FLAG_JIT);
    vm=randomx_create_vm(flags,cache,nullptr); need(vm!=nullptr,"RandomX light VM creation");
    cache_key=key; initialized=true;
  }
  const auto blob=cryptonote::get_block_hashing_blob(b); crypto::hash out;
  randomx_calculate_hash(vm,blob.data(),blob.size(),&out); ++hashes; return out;
}
Template Ledger::mining_template(const crypto::public_key& destination,uint64_t timestamp) {
  std::lock_guard<std::recursive_mutex> lock(mutex); const auto& p=blocks.at(tip_id);
  need(p.height<std::numeric_limits<uint64_t>::max()-60,"height overflow");
  Template t{}; t.height=p.height+1; t.difficulty=next(p); t.seed=seed(p,t.height);
  auto& b=t.block; b.major_version=16; b.minor_version=0; b.prev_id=cryptonote::get_block_hash(p.block);
  b.timestamp=timestamp ? timestamp : std::max(wall_time(),p.block.timestamp+120);
  need(b.timestamp>=median(p)&&b.timestamp<=wall_time()+7200,"template timestamp outside admission window");
  b.miner_tx.version=1; b.miner_tx.unlock_time=t.height+60;
  b.miner_tx.vin.push_back(cryptonote::txin_gen{t.height});
  b.miner_tx.vout.push_back(cryptonote::tx_out{phase0::payout(p.issued,0),cryptonote::txout_to_key{destination}});
  need(cryptonote::add_extra_nonce_to_tx_extra(b.miner_tx.extra,"PrivacyCoinDev01/public-coinbase-v1"),"coinbase domain");
  return t;
}
Entry Ledger::validate(const std::string& bytes,const std::string& claimed,uint64_t now) {
  need(!bytes.empty()&&bytes.size()<=300000,"block size/weight");
  Entry e; e.bytes=bytes;
  need(cryptonote::parse_and_validate_block_from_blob(bytes,e.block),"malformed block");
  need(cryptonote::block_to_blob(e.block)==bytes,"noncanonical block/trailing data");
  auto& b=e.block; e.id=hex(cryptonote::get_block_hash(b));
  need(!blocks.count(e.id),"duplicate block");
  e.parent=hex(b.prev_id); need(blocks.count(e.parent),"unknown previous block");
  const auto& p=blocks.at(e.parent); need(p.height<std::numeric_limits<uint64_t>::max()-60,"height overflow");
  e.height=p.height+1; e.difficulty=next(p);
  need(claimed.empty()||claimed==e.difficulty.convert_to<std::string>(),"invalid claimed difficulty");
  need(b.major_version==16&&b.minor_version==0,"unsupported block version");
  need(b.timestamp>=median(p),"timestamp below median");
  need(now<=std::numeric_limits<uint64_t>::max()-7200 && b.timestamp<=now+7200,"timestamp too far in future");
  need(b.tx_hashes.empty(),"ordinary transactions/fees unsupported in Phase 1");
  const auto& tx=b.miner_tx;
  need(tx.version==1&&tx.unlock_time==e.height+60,"coinbase version/maturity");
  need(tx.vin.size()==1&&tx.vin.front().type()==typeid(cryptonote::txin_gen),"coinbase generation input");
  need(boost::get<cryptonote::txin_gen>(tx.vin.front()).height==e.height,"coinbase height");
  need(tx.signatures.size()<=1 && std::all_of(tx.signatures.begin(),tx.signatures.end(),[](const auto& s){return s.empty();}) && tx.rct_signatures.type==rct::RCTTypeNull,"coinbase proofs/signatures");
  need(tx.vout.size()==1&&cryptonote::check_outs_valid(tx),"coinbase outputs");
  need(tx.vout.front().target.type()==typeid(cryptonote::txout_to_key),"coinbase output type");
  public_key(hex(boost::get<cryptonote::txout_to_key>(tx.vout.front().target).key));
  std::vector<uint8_t> expected_extra;
  need(cryptonote::add_extra_nonce_to_tx_extra(expected_extra,"PrivacyCoinDev01/public-coinbase-v1")&&tx.extra==expected_extra,"coinbase network domain/extra");
  need(tx.vout.front().amount==phase0::payout(p.issued,0),"coinbase subsidy/fee accounting");
  need(phase0::pow_valid(hash(b,seed(p,e.height)),e.difficulty),"invalid RandomX PoW");
  e.work=phase0::add_work(p.work,e.difficulty); e.issued=phase0::add_issuance(p.issued,phase0::subsidy(p.issued));
  return e;
}
void Ledger::store(const Entry& e,const std::string& selected) {
  if(!db) return;
  MDB_txn* t=nullptr; dbcheck(mdb_txn_begin(db,nullptr,0,&t));
  try { dbput(t,dbi,"b:"+e.id,e.bytes); dbput(t,dbi,"tip",selected); auto* committing=t;t=nullptr;dbcheck(mdb_txn_commit(committing)); }
  catch(...) { if(t) mdb_txn_abort(t); throw; }
}
void Ledger::select(const std::string& id) {
  const auto old=active_chain(); tip_id=id; const auto current=active_chain();
  size_t common=0; while(common<old.size()&&common<current.size()&&old[common]==current[common]) ++common;
  if(common<old.size()) { ++reorganizations; disconnected+=old.size()-common; }
}
std::string Ledger::submit(const std::string& bytes,const std::string& claimed,uint64_t now) {
  std::lock_guard<std::recursive_mutex> lock(mutex); const auto started=std::chrono::steady_clock::now();
  auto e=validate(bytes,claimed,now); const bool wins=phase0::replaces(e.work,blocks.at(tip_id).work);
  store(e,wins?e.id:tip_id); blocks.emplace(e.id,e); if(wins) select(e.id);
  ++accepted; validation_ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-started).count();
  return e.id;
}
}
