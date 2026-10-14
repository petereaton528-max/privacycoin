// Phase 4 integration of frozen Phase 1 ledger; see ADR-0003. Primitives unchanged.
#pragma once
#include <chrono>
#include <atomic>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <set>
#include "consensus/development_profile.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "randomx.h"
#include "lmdb.h"
#include "persistent_index.h"

namespace pcdev {
inline std::string network = "PrivacyCoinDev01";
inline constexpr uint16_t default_p2p_port=48080, default_rpc_port=48081;
inline constexpr char genesis_id[] = "a0d9ba16f1f6b2fb2f480197ff9dec17468db0d5e6df9cfcb4b2b2a91ecffc87";
inline constexpr char genesis_bytes[] = "100000000000000000000000000000000000000000000000000000000000000000000000000000010001ff000037023550726976616379436f696e2f7068617365302f6465766e65742f67656e657369732f76312f50726976616379436f696e446576303100";
inline std::string identity = "PrivacyCoinDev01/private-spend-v1-hardening/epoch18/a0d9ba16f1f6b2fb2f480197ff9dec17468db0d5e6df9cfcb4b2b2a91ecffc87";
inline constexpr char tx_domain[]="PrivacyCoinDev01/private-spend-v1-hardening";
struct Output { crypto::public_key key; rct::key commitment; uint64_t height,unlock,index; std::string transaction; };
struct State { BranchVector<Output> outputs; BranchSet<std::string> images,transactions,output_keys; };
inline constexpr char reward_key[] = "5866666666666666666666666666666666666666666666666666666666666666";
std::string hex(const void*, size_t);
std::string unhex(const std::string&);
template<class T> std::string hex(const T& p) { return hex(&p, sizeof(p)); }
uint64_t wall_time();
struct Entry {
  cryptonote::block block;
  std::string bytes, id, parent;
  uint64_t height = 0;
  cryptonote::difficulty_type difficulty = 0;
  phase0::wide work = 0, issued = 0;
  State state;
};
struct Template {
  cryptonote::block block;
  cryptonote::difficulty_type difficulty;
  crypto::hash seed;
  uint64_t height;
};
class Ledger {
 public:
  explicit Ledger(const std::string& directory = "",uint64_t pool_ttl=3600,size_t initial_map_bytes=1024ULL*1024*1024);
  ~Ledger();
  Ledger(const Ledger&) = delete;
  Ledger& operator=(const Ledger&) = delete;
  Template mining_template(const crypto::public_key&, uint64_t timestamp = 0, const crypto::public_key& R=crypto::null_pkey);
  std::string submit(const std::string& bytes, const std::string& claimed_difficulty = "", uint64_t now = wall_time());
  crypto::hash hash(const cryptonote::block&, const crypto::hash&);
  Entry tip();
  Entry get(const std::string&);
  std::vector<Entry> entries();
  std::vector<std::string> active_chain();
  std::string submit_transaction(const std::string&);
  std::string transaction(const std::string&);
  void import_transaction(const std::string&);
  std::vector<std::string> pool_inventory();
  std::vector<std::pair<std::string,std::string>> pool_entries();
  void cleanup_pool(uint64_t now=wall_time());
  std::unique_lock<std::recursive_mutex> guard(){return std::unique_lock<std::recursive_mutex>(mutex);}
  std::vector<std::string> orphan_images();
  std::vector<std::string> orphan_images_after(const std::string&,size_t);
  std::string instance;
  std::atomic<uint64_t> pool_revision{0};
  std::atomic<uint64_t> pool_expired{0},pool_stale{0};
  std::atomic<double> transaction_validation_ms{0};
  std::atomic<double> transaction_verify_ms{0},pool_commit_ms{0};
  std::atomic<uint64_t> hashes{0}, accepted{0}, reorganizations{0}, disconnected{0};
  std::atomic<double> validation_ms{0};
 private:
  std::recursive_mutex mutex;
  std::map<std::string, Entry> blocks;
  std::string tip_id;
  std::map<std::string,std::string> transactions,pool;
  std::set<std::string> staged_transactions;
  std::map<std::string,uint64_t> pool_times;
  uint64_t pool_ttl;
  bool loading_pool=false;
  void persist_pool();
  void grow_map();
  void write_pool(MDB_txn*);
  MDB_env* db = nullptr;
  MDB_dbi dbi = 0;
  randomx_cache* cache = nullptr;
  randomx_vm* vm = nullptr;
  crypto::hash cache_key{};
  bool initialized = false;
  Entry validate(const std::string&, const std::string&, uint64_t);
  cryptonote::difficulty_type next(const Entry&);
  crypto::hash seed(const Entry&, uint64_t);
  uint64_t median(const Entry&);
  void store(const Entry&, const std::string&);
  void select(const std::string&);
  uint64_t validate_transaction(const std::string&,State&,uint64_t);
  void append_outputs(const cryptonote::transaction&,State&,uint64_t,bool);
};
crypto::public_key public_key(const std::string&);
void self_test();
extern std::string crash_stage;
void fault(const char*);
}
