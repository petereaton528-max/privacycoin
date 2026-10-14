#include <cstring>
#include <iostream>
#include <string>
#include "consensus/development_profile.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "randomx.h"

static unsigned checks = 0;
static void require(bool ok, const char* name) {
  if (!ok) throw std::runtime_error(name);
  ++checks;
}
template<class F> static void rejects(F function, const char* name) {
  bool failed = false;
  try { function(); } catch (const std::exception&) { failed = true; }
  require(failed, name);
}
static std::string hex(const void* data, size_t count) {
  const auto* p = static_cast<const unsigned char*>(data);
  const char* alphabet = "0123456789abcdef";
  std::string result;
  for (size_t i=0; i<count; ++i) { result += alphabet[p[i] >> 4]; result += alphabet[p[i] & 15]; }
  return result;
}
static cryptonote::block genesis() {
  cryptonote::block b{};
  b.major_version=16; b.minor_version=0; b.timestamp=0; b.nonce=0;
  b.prev_id=crypto::null_hash;
  b.miner_tx.version=1; b.miner_tx.unlock_time=0;
  b.miner_tx.vin.push_back(cryptonote::txin_gen{0});
  b.miner_tx.vout.clear(); // Explicit genesis-only zero-issuance exception.
  const std::string domain="PrivacyCoin/phase0/devnet/genesis/v1/PrivacyCoinDev01";
  if (!cryptonote::add_extra_nonce_to_tx_extra(b.miner_tx.extra, domain))
    throw std::runtime_error("genesis domain");
  return b;
}
static crypto::hash randomx_hash(const std::string& blob, const crypto::hash& key) {
  auto* cache=randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
  if (!cache) throw std::runtime_error("RandomX cache allocation");
  randomx_init_cache(cache, &key, sizeof(key));
  auto* vm=randomx_create_vm(RANDOMX_FLAG_DEFAULT, cache, nullptr);
  if (!vm) { randomx_release_cache(cache); throw std::runtime_error("RandomX VM creation"); }
  crypto::hash hash{};
  randomx_calculate_hash(vm, blob.data(), blob.size(), &hash);
  randomx_destroy_vm(vm); randomx_release_cache(cache);
  return hash;
}
static void print_genesis() {
  auto b=genesis();
  auto bytes=cryptonote::block_to_blob(b);
  auto blob=cryptonote::get_block_hashing_blob(b);
  auto id=cryptonote::get_block_hash(b);
  auto digest=randomx_hash(blob,id);
  require(phase0::pow_valid(digest,1),"genesis real PoW");
  std::cout << "{\n  \"profile\": \"phase0-devnet-v1\",\n"
    << "  \"network_id_hex\": \"50726976616379436f696e4465763031\",\n"
    << "  \"timestamp\": 0,\n  \"nonce\": 0,\n  \"difficulty\": 1,\n"
    << "  \"genesis_work\": 0,\n  \"reward\": 0,\n"
    << "  \"coinbase_version\": 1,\n  \"generation_height\": 0,\n  \"outputs\": 0,\n"
    << "  \"serialized_hex\": \"" << hex(bytes.data(),bytes.size()) << "\",\n"
    << "  \"hashing_blob_hex\": \"" << hex(blob.data(),blob.size()) << "\",\n"
    << "  \"block_hash\": \"" << hex(&id,sizeof(id)) << "\",\n"
    << "  \"randomx_digest\": \"" << hex(&digest,sizeof(digest)) << "\"\n}\n";
}
static void print_reward_heights() {
  phase0::wide issued=0;
  std::cout << "[\n";
  bool first=true;
  for (unsigned height=1; height<=10000; ++height) {
    const auto reward=phase0::subsidy(issued);
    if (height==1 || height==2 || height==100 || height==10000) {
      if (!first) std::cout << ",\n";
      std::cout << "  {\"height\": " << height << ", \"parent_issued\": \""
        << issued << "\", \"subsidy\": " << reward << "}";
      first=false;
    }
    issued=phase0::add_issuance(issued,reward); // Only subsidy advances issuance; no fees.
  }
  std::cout << "\n]\n";
}
int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "--genesis") { print_genesis(); return 0; }
    if (argc == 2 && std::string(argv[1]) == "--reward-heights") { print_reward_heights(); return 0; }
    using namespace phase0;
    crypto::hash zero{}, maximum{}, boundary{};
    std::memset(&maximum,255,sizeof(maximum)); boundary=maximum;
    reinterpret_cast<unsigned char*>(&boundary)[31]=127;
    require(pow_valid(zero,1),"zero hash positive D");
    require(!pow_valid(zero,0),"zero difficulty rejected");
    require(pow_valid(maximum,1),"D1 maximum accepted");
    require(!pow_valid(maximum,2),"invalid PoW rejected");
    require(pow_valid(boundary,2),"D2 exact boundary");
    reinterpret_cast<unsigned char*>(&boundary)[31]=128;
    std::memset(&boundary,0,31);
    require(!pow_valid(boundary,2),"D2 boundary plus one");
    require(pow_valid(zero,std::numeric_limits<cryptonote::difficulty_type>::max()),"128bit D");
    require(difficulty({}, {})==1,"DAA startup");
    require(difficulty({0,120},{1,2})==1,"DAA target spacing");
    require(difficulty({0,60},{1,2})==2,"DAA double rate");
    require(difficulty({0,121},{1,3})==2,"DAA ceiling");
    require(difficulty({42,42},{1,2})==120,"DAA equal timestamps");
    std::vector<uint64_t> times; std::vector<cryptonote::difficulty_type> work;
    for(unsigned i=0;i<735;++i) { times.push_back(i*120); work.push_back(i+1); }
    require(difficulty(times,work)==1,"DAA full window and lag");
    times[734]=std::numeric_limits<uint64_t>::max(); work[734]=100000;
    require(difficulty(times,work)==1,"DAA excludes newest fifteen");
    rejects([&] { difficulty({0,1},{1,std::numeric_limits<cryptonote::difficulty_type>::max()}); },"DAA overflow");
    for (auto p : {std::pair<uint64_t,uint64_t>{0,0},{64,0},{65,0},{2112,0},{2113,2048},{4160,2048},{4161,4096}})
      require(seed_height(p.first)==p.second,"seed schedule");
    const wide m=std::numeric_limits<uint64_t>::max(); const wide tail=600000000000ULL;
    require(subsidy(0)==35184372088831ULL,"first block reward");
    require(subsidy(wide(35184372088831ULL))==35184304979968ULL,"second issuance state");
    const wide transition=m-((tail+1)<<19);
    require(subsidy(transition)==600000000001ULL,"last above-tail state");
    require(subsidy(transition+1)==600000000000ULL,"tail boundary");
    require(subsidy(m)==600000000000ULL && subsidy(m+1)==600000000000ULL,"saturating supply");
    require(genesis().miner_tx.vout.empty(),"zero genesis issuance");
    require(!mature(100,159) && mature(100,160),"maturity boundary");
    require(!mature(std::numeric_limits<uint64_t>::max(),0),"maturity underflow");
    require(payout(0,123)==35184372088954ULL,"reward plus fees");
    rejects([&] { payout(0,m); },"payout overflow");
    rejects([&] { payout(0,std::numeric_limits<wide>::max()); },"wide fee overflow");
    require(add_issuance(0,subsidy(0))==35184372088831ULL,"fees do not mint supply");
    rejects([&] { add_issuance(std::numeric_limits<wide>::max(),1); },"issuance overflow");
    require(replaces(add_work(10,2),11),"higher work wins");
    require(!replaces(12,12) && !replaces(11,12),"equal work retains tip");
    rejects([&] { add_work(std::numeric_limits<wide>::max(),1); },"chain work overflow");
    rejects([&] { add_work(0,0); },"zero block work rejected");
    auto b=genesis(); const auto original=cryptonote::get_block_hashing_blob(b);
    b.nonce=1;
    require(original!=cryptonote::get_block_hashing_blob(b),"template commits nonce");
    b=genesis(); b.timestamp=1;
    require(original!=cryptonote::get_block_hashing_blob(b),"template commits timestamp");
    b=genesis(); b.miner_tx.extra.push_back(0);
    require(original!=cryptonote::get_block_hashing_blob(b),"template commits coinbase root");
    auto digest=randomx_hash(original,cryptonote::get_block_hash(genesis()));
    require(pow_valid(digest,1),"actual RandomX PoW accepted");
    require(!pow_valid(digest,std::numeric_limits<cryptonote::difficulty_type>::max()),"actual RandomX PoW invalid at extreme D");
    std::cout << "PASS " << checks << " Phase 0 mining/consensus checks\n";
  } catch(const std::exception& error) { std::cerr << "FAIL: " << error.what() << "\n"; return 1; }
}
