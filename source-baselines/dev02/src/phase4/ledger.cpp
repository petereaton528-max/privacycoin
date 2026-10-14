#include "ledger.h"
#include <cstring>
#include <iostream>
#include <limits>
#include <iterator>
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "cryptonote_basic/tx_extra.h"
#include <sodium.h>
#include "platform_interrupt.h"

namespace pcdev {
std::string crash_stage;
void fault(const char* stage){if(crash_stage==stage)interrupt_self();}
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
  need(crypto_core_ed25519_is_valid_point(reinterpret_cast<const unsigned char*>(&p))==1,"noncanonical point");
  return p;
}
struct DatabaseError:std::runtime_error {int code;explicit DatabaseError(int c):std::runtime_error(std::string("LMDB: ")+mdb_strerror(c)),code(c){}};
static void dbcheck(int rc) { if(rc) throw DatabaseError(rc); }
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
Ledger::Ledger(const std::string& directory,uint64_t ttl,size_t initial_map_bytes):pool_ttl(ttl) {
  need(ttl>0&&ttl<=86400,"mempool TTL bounds");
  instance=hex(crypto::rand<crypto::hash>());
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
    need(initial_map_bytes>=65536,"LMDB initial map too small");
    dbcheck(mdb_env_create(&db)); dbcheck(mdb_env_set_mapsize(db,initial_map_bytes));
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
      std::vector<std::pair<std::string,std::string>> saved_pool;
      MDB_cursor* cursor=nullptr; dbcheck(mdb_cursor_open(t,dbi,&cursor));
      MDB_val k{},v{}; int rc=mdb_cursor_get(cursor,&k,&v,MDB_FIRST);
      while(rc==0) {
        std::string key(static_cast<char*>(k.mv_data),k.mv_size);
        if(key.rfind("b:",0)==0) saved.emplace_back(key.substr(2),std::string(static_cast<char*>(v.mv_data),v.mv_size));
        else if(key.rfind("t:",0)==0) { import_transaction(std::string(static_cast<char*>(v.mv_data),v.mv_size)); need(transactions.count(key.substr(2)),"persisted transaction key mismatch");staged_transactions.erase(key.substr(2)); }
        else if(key.rfind("p:",0)==0)saved_pool.emplace_back(key.substr(2),std::string(static_cast<char*>(v.mv_data),v.mv_size));
        else need(key=="identity"||key=="tip","unknown database record");
        rc=mdb_cursor_get(cursor,&k,&v,MDB_NEXT);
      }
      mdb_cursor_close(cursor); need(rc==MDB_NOTFOUND,"database cursor error");
      // Queue parent dependencies once. Every block is still fully validated,
      // including PoW; no persisted height, state or work is trusted.
      std::map<std::string,std::vector<size_t>> children;
      for(size_t i=0;i<saved.size();++i){
        cryptonote::block b;
        need(saved[i].second.size()<=300000&&cryptonote::parse_and_validate_block_from_blob(saved[i].second,b),"corrupt persisted block");
        children[hex(b.prev_id)].push_back(i);
      }
      std::vector<std::string> ready{genesis_id};size_t loaded=0;
      for(size_t cursor=0;cursor<ready.size();++cursor){
        const auto found=children.find(ready[cursor]);if(found==children.end())continue;
        for(auto i:found->second){
          auto e=validate(saved[i].second,"",wall_time());
          need(e.id==saved[i].first,"persisted block key mismatch");
          if(phase0::replaces(e.work,blocks.at(tip_id).work))tip_id=e.id;
          ready.push_back(e.id);blocks.emplace(e.id,e);++loaded;
        }
      }
      need(loaded==saved.size(),"orphan/corrupt persisted block graph");
      need(blocks.count(saved_tip)&&blocks.at(saved_tip).work==blocks.at(tip_id).work,"corrupt persisted tip");
      tip_id=saved_tip;
      auto* committing=t; t=nullptr; dbcheck(mdb_txn_commit(committing));
      loading_pool=true;
      for(const auto& item:saved_pool){auto split=item.second.find('\n');need(split!=std::string::npos&&split<21,"corrupt pool timestamp");
        size_t used=0;uint64_t receipt=std::stoull(item.second.substr(0,split),&used);need(used==split&&std::to_string(receipt)==item.second.substr(0,split)&&receipt<=wall_time()+300,"corrupt pool timestamp");
        auto raw=item.second.substr(split+1);cryptonote::transaction tx;need(cryptonote::parse_and_validate_tx_from_blob(raw,tx)&&cryptonote::tx_to_blob(tx)==raw&&hex(cryptonote::get_transaction_hash(tx))==item.first,"corrupt pool record");
        if(wall_time()>=receipt&&wall_time()-receipt>=pool_ttl){++pool_expired;continue;}
        try{auto id=submit_transaction(raw);pool_times[id]=receipt;}catch(...){++pool_stale;}}
      loading_pool=false;persist_pool();
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
  std::vector<uint64_t> t; auto e=&p;
  while(e->height>0 && t.size()<60) { t.push_back(e->block.timestamp); e=&blocks.at(e->parent); }
  if(t.empty()) return 0;
  return epee::misc_utils::median(t);
}
cryptonote::difficulty_type Ledger::next(const Entry& p) {
  std::vector<uint64_t> times;
  std::vector<phase0::wide> totals;
  std::vector<cryptonote::difficulty_type> work;
  auto e=&p; phase0::wide max=std::numeric_limits<cryptonote::difficulty_type>::max();
  while(e->height>0 && times.size()<735) {
    times.push_back(e->block.timestamp); totals.push_back(e->work);
    e=&blocks.at(e->parent);
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
  const auto target=phase0::seed_height(h); auto e=&p;
  while(e->height>target) e=&blocks.at(e->parent);
  need(e->height==target,"missing branch RandomX seed");
  return cryptonote::get_block_hash(e->block);
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
Template Ledger::mining_template(const crypto::public_key& destination,uint64_t timestamp,const crypto::public_key& R) {
  std::lock_guard<std::recursive_mutex> lock(mutex); cleanup_pool();const auto& p=blocks.at(tip_id);
  need(p.height<std::numeric_limits<uint64_t>::max()-60,"height overflow");
  Template t{}; t.height=p.height+1; t.difficulty=next(p); t.seed=seed(p,t.height);
  auto& b=t.block; b.major_version=18; b.minor_version=0; b.prev_id=cryptonote::get_block_hash(p.block);
  b.timestamp=timestamp ? timestamp : std::max(wall_time(),p.block.timestamp+120);
  need(b.timestamp>=median(p)&&b.timestamp<=wall_time()+7200,"template timestamp outside admission window");
  need(R!=crypto::null_pkey,"private coinbase transaction public key required");public_key(hex(R));public_key(hex(destination));
  b.miner_tx.version=2; b.miner_tx.unlock_time=t.height+60;
  b.miner_tx.vin.push_back(cryptonote::txin_gen{t.height});
  uint64_t fees=0;size_t weight=1024;State state=p.state;
  for(const auto& item:pool) {
    if(b.tx_hashes.size()==8)break;
    if(weight+item.second.size()>300000)continue;
    try { auto fee=validate_transaction(item.second,state,t.height);need(fees<=UINT64_MAX-fee,"fee overflow");fees+=fee;
      crypto::hash id;auto raw=unhex(item.first);std::memcpy(&id,raw.data(),32);b.tx_hashes.push_back(id);weight+=item.second.size();
    } catch(...) {}
  }
  b.miner_tx.vout.push_back(cryptonote::tx_out{phase0::payout(p.issued,fees),cryptonote::txout_to_key{destination}});
  cryptonote::add_tx_pub_key_to_extra(b.miner_tx,R);
  need(cryptonote::add_extra_nonce_to_tx_extra(b.miner_tx.extra,tx_domain),"coinbase domain");
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
  need(b.major_version==18&&b.minor_version==0,"unsupported block version");
  need(b.timestamp>=median(p),"timestamp below median");
  need(now<=std::numeric_limits<uint64_t>::max()-7200 && b.timestamp<=now+7200,"timestamp too far in future");
  need(b.tx_hashes.size()<=8,"transaction count limit");e.state=p.state;uint64_t fees=0;size_t weight=bytes.size();
  for(const auto& id:b.tx_hashes) {
    const auto tid=hex(id);need(transactions.count(tid),"missing transaction body");const auto& raw=transactions.at(tid);
    need(weight<=300000-raw.size(),"combined block weight");weight+=raw.size();
    auto fee=validate_transaction(raw,e.state,e.height);need(fees<=UINT64_MAX-fee,"fee overflow");fees+=fee;
  }
  const auto& tx=b.miner_tx;
  need(tx.version==2&&tx.unlock_time==e.height+60,"coinbase version/maturity");
  need(tx.vin.size()==1&&tx.vin.front().type()==typeid(cryptonote::txin_gen),"coinbase generation input");
  need(boost::get<cryptonote::txin_gen>(tx.vin.front()).height==e.height,"coinbase height");
  need(tx.signatures.size()<=1 && std::all_of(tx.signatures.begin(),tx.signatures.end(),[](const auto& s){return s.empty();}) && tx.rct_signatures.type==rct::RCTTypeNull,"coinbase proofs/signatures");
  need(tx.vout.size()==1&&cryptonote::check_outs_valid(tx),"coinbase outputs");
  need(tx.vout.front().target.type()==typeid(cryptonote::txout_to_key),"coinbase output type");
  public_key(hex(boost::get<cryptonote::txout_to_key>(tx.vout.front().target).key));
  std::vector<uint8_t> expected_extra;
  const auto R=cryptonote::get_tx_pub_key_from_extra(tx);public_key(hex(R));
  cryptonote::transaction extra_holder;cryptonote::add_tx_pub_key_to_extra(extra_holder,R);expected_extra=extra_holder.extra;
  need(cryptonote::add_extra_nonce_to_tx_extra(expected_extra,tx_domain)&&tx.extra==expected_extra,"coinbase network domain/extra");
  need(tx.vout.front().amount==phase0::payout(p.issued,fees),"coinbase subsidy/fee accounting");
  need(phase0::pow_valid(hash(b,seed(p,e.height)),e.difficulty),"invalid RandomX PoW");
  e.work=phase0::add_work(p.work,e.difficulty); e.issued=phase0::add_issuance(p.issued,phase0::subsidy(p.issued));
  append_outputs(tx,e.state,e.height,true);
  for(const auto& id:b.tx_hashes){cryptonote::transaction normal;need(cryptonote::parse_and_validate_tx_from_blob(transactions.at(hex(id)),normal),"transaction parse");append_outputs(normal,e.state,e.height,false);}
  return e;
}
void Ledger::store(const Entry& e,const std::string& selected) {
  if(!db) return;
  for(;;){
  MDB_txn* t=nullptr; dbcheck(mdb_txn_begin(db,nullptr,0,&t));
  try { dbput(t,dbi,"b:"+e.id,e.bytes);for(const auto& id:e.block.tx_hashes)dbput(t,dbi,"t:"+hex(id),transactions.at(hex(id)));dbput(t,dbi,"tip",selected);write_pool(t);fault("before_block_commit");auto* committing=t;t=nullptr;dbcheck(mdb_txn_commit(committing));fault("after_block_commit");return; }
  catch(const DatabaseError& error){if(t)mdb_txn_abort(t);if(error.code!=MDB_MAP_FULL)throw;grow_map();}
  catch(...) { if(t) mdb_txn_abort(t); throw; }
  }
}
void Ledger::grow_map(){
  // All transactions are closed and the Ledger mutex serializes this process.
  // Other processes must not share this owned database (enforced by launcher).
  MDB_envinfo info{};dbcheck(mdb_env_info(db,&info));
  constexpr size_t step=256ULL*1024*1024;
  need(info.me_mapsize<=std::numeric_limits<size_t>::max()-step,"LMDB address space exhausted");
  dbcheck(mdb_env_set_mapsize(db,info.me_mapsize+step));
}
void Ledger::select(const std::string& id) {
  // The usual append does not need two full-chain walks or pool replay.
  if(blocks.at(id).parent==tip_id&&pool.empty()) {tip_id=id;++pool_revision;return;}
  const auto old=active_chain(); tip_id=id; const auto current=active_chain();
  size_t common=0; while(common<old.size()&&common<current.size()&&old[common]==current[common]) ++common;
  if(common<old.size()) { ++reorganizations; disconnected+=old.size()-common; }
  auto candidates=pool;auto receipt_times=pool_times;pool.clear();pool_times.clear();loading_pool=true;
  for(size_t i=common;i<old.size();++i)for(const auto& txid:blocks.at(old[i]).block.tx_hashes)candidates.emplace(hex(txid),transactions.at(hex(txid)));
  for(const auto& item:candidates)try{auto tid=submit_transaction(item.second);if(receipt_times.count(tid))pool_times[tid]=receipt_times[tid];}catch(...){++pool_stale;}
  loading_pool=false;++pool_revision;if(common<old.size())fault("reorg_publish");
}
std::string Ledger::submit(const std::string& bytes,const std::string& claimed,uint64_t now) {
  std::lock_guard<std::recursive_mutex> lock(mutex); const auto started=std::chrono::steady_clock::now();
  auto e=validate(bytes,claimed,now); const bool wins=phase0::replaces(e.work,blocks.at(tip_id).work);
  const auto previous_tip=tip_id;auto previous_pool=pool;auto previous_times=pool_times;blocks.emplace(e.id,e);
  try{if(wins)select(e.id);store(e,wins?e.id:tip_id);}
  catch(...){tip_id=previous_tip;pool=std::move(previous_pool);pool_times=std::move(previous_times);blocks.erase(e.id);throw;}
  // Snapshot metadata also covers orphan branches. A new losing block changes
  // that view even when canonical tip and mempool stay unchanged.
  if(!wins)++pool_revision;
  for(const auto& id:e.block.tx_hashes)staged_transactions.erase(hex(id));
  ++accepted; validation_ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-started).count();
  return e.id;
}
void Ledger::import_transaction(const std::string& raw) {
  std::lock_guard<std::recursive_mutex> lock(mutex);
  need(!raw.empty()&&raw.size()<=50000,"transaction size");cryptonote::transaction tx;
  need(cryptonote::parse_and_validate_tx_from_blob(raw,tx)&&cryptonote::tx_to_blob(tx)==raw,"noncanonical transaction");
  need(tx.version==2&&tx.rct_signatures.type==rct::RCTTypeBulletproofPlus,"unsupported transaction version/scheme");
  const auto id=hex(cryptonote::get_transaction_hash(tx));
  need(transactions.count(id)||staged_transactions.size()<8192,"uncommitted transaction staging limit");
  if(transactions.emplace(id,raw).second)staged_transactions.insert(id);
}
std::string Ledger::transaction(const std::string& id) {std::lock_guard<std::recursive_mutex> lock(mutex);return transactions.at(id);}
std::vector<std::string> Ledger::pool_inventory(){std::lock_guard<std::recursive_mutex> lock(mutex);cleanup_pool();std::vector<std::string> ids;for(const auto& i:pool)ids.push_back(i.first);return ids;}
std::vector<std::pair<std::string,std::string>> Ledger::pool_entries(){std::lock_guard<std::recursive_mutex> lock(mutex);cleanup_pool();return {pool.begin(),pool.end()};}
void Ledger::write_pool(MDB_txn* t){
  MDB_cursor* c=nullptr;dbcheck(mdb_cursor_open(t,dbi,&c));MDB_val k{},v{};int rc=mdb_cursor_get(c,&k,&v,MDB_FIRST);
  while(rc==0){std::string key(static_cast<const char*>(k.mv_data),k.mv_size);if(key.rfind("p:",0)==0)dbcheck(mdb_cursor_del(c,0));rc=mdb_cursor_get(c,&k,&v,MDB_NEXT);}
  mdb_cursor_close(c);need(rc==MDB_NOTFOUND,"pool database cursor");
  for(const auto& item:pool)dbput(t,dbi,"p:"+item.first,std::to_string(pool_times.at(item.first))+"\n"+item.second);
}
void Ledger::persist_pool(){
  if(!db||loading_pool)return;
  for(;;){MDB_txn* t=nullptr;dbcheck(mdb_txn_begin(db,nullptr,0,&t));
  try{write_pool(t);
    fault("before_pool_commit");auto* committing=t;t=nullptr;dbcheck(mdb_txn_commit(committing));fault("after_pool_commit");return;
  }catch(const DatabaseError& error){if(t)mdb_txn_abort(t);if(error.code!=MDB_MAP_FULL)throw;grow_map();}
  catch(...){if(t)mdb_txn_abort(t);throw;}}
}
void Ledger::cleanup_pool(uint64_t now){std::lock_guard<std::recursive_mutex> lock(mutex);bool changed=false;
  for(auto i=pool.begin();i!=pool.end();){auto receipt=pool_times.at(i->first);if(now>=receipt&&now-receipt>=pool_ttl){pool_times.erase(i->first);i=pool.erase(i);++pool_expired;changed=true;}else ++i;}
  if(changed){++pool_revision;persist_pool();}
}
std::vector<std::string> Ledger::orphan_images(){return orphan_images_after("",SIZE_MAX);}
std::vector<std::string> Ledger::orphan_images_after(const std::string& after,size_t count){std::lock_guard<std::recursive_mutex> lock(mutex);auto selected=active_chain();std::set<std::string> canonical(selected.begin(),selected.end()),images;
  // Bounded lexicographic page, including at most one look-ahead item. Never
  // materialize every orphan key image merely to serialize a small RPC page.
  for(const auto& item:blocks)if(!canonical.count(item.first))for(const auto& id:item.second.block.tx_hashes){cryptonote::transaction tx;need(cryptonote::parse_and_validate_tx_from_blob(transactions.at(hex(id)),tx),"stored transaction parse");for(const auto& v:tx.vin){auto image=hex(boost::get<cryptonote::txin_to_key>(v).k_image);if(image>after){images.insert(image);if(images.size()>count)images.erase(std::prev(images.end()));}}}
  return {images.begin(),images.end()};
}
void Ledger::append_outputs(const cryptonote::transaction& tx,State& state,uint64_t height,bool coinbase) {
  const auto id=hex(cryptonote::get_transaction_hash(tx));
  for(size_t i=0;i<tx.vout.size();++i){const auto& out=tx.vout[i];
    auto P=boost::get<cryptonote::txout_to_key>(out.target).key;
    need(state.outputs.size()<UINT64_MAX&&(!coinbase||state.output_keys.insert(hex(P)).second),"output index overflow or repeated one-time destination");
    state.outputs.push_back(Output{P,coinbase?rct::zeroCommit(out.amount):tx.rct_signatures.outPk.at(i).mask,
      height,coinbase?height+60:height+10,i,id});
  }
  state.transactions.insert(id);
}
uint64_t Ledger::validate_transaction(const std::string& raw,State& state,uint64_t height) {
  need(!raw.empty()&&raw.size()<=50000,"transaction size");cryptonote::transaction tx;
  need(cryptonote::parse_and_validate_tx_from_blob(raw,tx)&&cryptonote::tx_to_blob(tx)==raw,"noncanonical transaction");
  auto& rv=tx.rct_signatures;
  need(tx.version==2&&rv.type==rct::RCTTypeBulletproofPlus,"unsupported transaction version/scheme");
  need(tx.unlock_time==0&&tx.signatures.empty()&&!tx.vin.empty()&&tx.vin.size()<=8&&tx.vout.size()>=2&&tx.vout.size()<=16,"transaction shape/unlock");
  const auto id=hex(cryptonote::get_transaction_hash(tx));need(!state.transactions.count(id),"transaction replay");
  std::set<std::string> images;
  for(const auto& v:tx.vin){need(v.type()==typeid(cryptonote::txin_to_key),"private input type");const auto& input=boost::get<cryptonote::txin_to_key>(v);
    need(input.amount==0&&input.key_offsets.size()==16,"ring size/private amount");public_key(hex(input.k_image));
    need(!state.images.count(hex(input.k_image))&&images.insert(hex(input.k_image)).second,"already spent or duplicate key image");}
  need(rv.txnFee>0&&rv.txnFee<=1000000000000ULL,"fee bounds");
  need(rv.p.CLSAGs.size()==tx.vin.size()&&rv.p.pseudoOuts.size()==tx.vin.size()&&rv.ecdhInfo.size()==tx.vout.size()&&rv.outPk.size()==tx.vout.size(),"proof structure");
  size_t rounds=6,padded=1;while(padded<tx.vout.size()){padded*=2;++rounds;}
  need(rv.p.bulletproofs_plus.size()==1&&rv.p.bulletproofs_plus[0].L.size()==rounds&&rv.p.bulletproofs_plus[0].R.size()==rounds,"aggregate range proof shape");
  std::vector<cryptonote::tx_extra_field> extra;need(tx.extra.size()<=1024&&cryptonote::parse_tx_extra(tx.extra,extra),"transaction extra");
  size_t pubs=0,nonces=0,additional=0;
  for(const auto& field:extra) {
    if(field.type()==typeid(cryptonote::tx_extra_pub_key)){++pubs;public_key(hex(boost::get<cryptonote::tx_extra_pub_key>(field).pub_key));}
    else if(field.type()==typeid(cryptonote::tx_extra_nonce)){++nonces;const auto& n=boost::get<cryptonote::tx_extra_nonce>(field).nonce;auto domainhash=crypto::cn_fast_hash(tx_domain,sizeof(tx_domain)-1);auto expected=std::string(1,'\0')+std::string(reinterpret_cast<const char*>(&domainhash),32);need(std::string(n.begin(),n.end())==expected,"transaction network/profile domain");}
    else if(field.type()==typeid(cryptonote::tx_extra_additional_pub_keys)){++additional;const auto& keys=boost::get<cryptonote::tx_extra_additional_pub_keys>(field).data;need(keys.size()==tx.vout.size(),"additional transaction keys");for(const auto& k:keys)public_key(hex(k));}
    else need(false,"unsupported transaction extra field");
  }
  need(pubs==1&&nonces==1&&additional<=1,"duplicate/missing transaction extra fields");
  std::vector<uint8_t> sorted;need(cryptonote::sort_tx_extra(tx.extra,sorted)&&sorted==tx.extra,"noncanonical extra order");
  std::set<std::string> destinations;
  for(size_t i=0;i<tx.vout.size();++i){const auto& out=tx.vout[i];need(out.amount==0&&out.target.type()==typeid(cryptonote::txout_to_key),"private output type/amount");auto key=hex(boost::get<cryptonote::txout_to_key>(out.target).key);public_key(key);public_key(hex(rv.outPk[i].mask));need(!state.output_keys.count(key)&&destinations.insert(key).second,"repeated one-time destination");}
  rv.mixRing.clear();rv.message=rct::hash2rct(cryptonote::get_transaction_prefix_hash(tx));
  for(size_t n=0;n<tx.vin.size();++n){const auto& input=boost::get<cryptonote::txin_to_key>(tx.vin[n]);need(rv.p.CLSAGs[n].s.size()==16,"CLSAG ring structure");
    rct::ctkeyV ring;uint64_t absolute=0;
    for(size_t i=0;i<16;++i){const auto offset=input.key_offsets[i];need(i==0||offset>0,"duplicate/unsorted ring index");need(absolute<=UINT64_MAX-offset,"ring offset overflow");absolute+=offset;
      need(absolute<state.outputs.size(),"ring index outside branch");const auto& out=state.outputs[absolute];need(out.unlock<=height,"immature ring member");ring.push_back(rct::ctkey{rct::pk2rct(out.key),out.commitment});}
    rv.mixRing.push_back(ring);rv.p.CLSAGs[n].I=rct::ki2rct(input.k_image);}
  need(rct::verRctSemanticsSimple(rv),"invalid commitment balance/range proof");
  need(rct::verRctNonSemanticsSimple(rv),"invalid CLSAG authorization/signed confidential data");
  state.images.insert(images.begin(),images.end());state.output_keys.insert(destinations.begin(),destinations.end());state.transactions.insert(id);return rv.txnFee;
}
std::string Ledger::submit_transaction(const std::string& raw) {
  std::lock_guard<std::recursive_mutex> lock(mutex);const auto began=std::chrono::steady_clock::now();cleanup_pool();need(pool.size()<32,"pool limit");
  State state=blocks.at(tip_id).state;
  for(const auto& item:pool)validate_transaction(item.second,state,blocks.at(tip_id).height+1);
  validate_transaction(raw,state,blocks.at(tip_id).height+1);import_transaction(raw);
  cryptonote::transaction tx;need(cryptonote::parse_and_validate_tx_from_blob(raw,tx),"transaction parse");need(tx.rct_signatures.txnFee>=100*raw.size(),"minimum relay fee: 100 atomic units per byte");
  const auto id=hex(cryptonote::get_transaction_hash(tx));need(!pool.count(id),"duplicate pool transaction");pool.emplace(id,raw);pool_times[id]=wall_time();
  transaction_verify_ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-began).count();const auto commit_started=std::chrono::steady_clock::now();
  try{persist_pool();}catch(...){pool.erase(id);pool_times.erase(id);throw;}pool_commit_ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-commit_started).count();++pool_revision;
  transaction_validation_ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-began).count();return id;
}
}
