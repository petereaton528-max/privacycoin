// Actual consensus/RandomX, fresh private databases only. No secret output.
#include "phase4/ledger.h"
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <numeric>
using namespace pcdev;
static void check(bool value,const char* name){if(!value)throw std::runtime_error(name);std::cout<<"PASS "<<name<<std::endl;}
static crypto::public_key fresh(){crypto::public_key p;crypto::secret_key s;crypto::generate_keys(p,s);return p;}
static std::string solve(Ledger& ledger,Template t){
  for(uint64_t n=0;n<=UINT32_MAX;++n){t.block.nonce=n;if(phase0::pow_valid(ledger.hash(t.block,t.seed),t.difficulty))return cryptonote::block_to_blob(t.block);}
  throw std::runtime_error("nonce exhausted");
}
static void metrics(uint64_t height,std::chrono::steady_clock::time_point start,const std::filesystem::path& path){
  rusage usage{};getrusage(RUSAGE_SELF,&usage);
  std::cout<<"METRIC height="<<height<<" elapsed_seconds="<<std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count()
    <<" peak_rss_kib="<<usage.ru_maxrss<<" database_bytes="<<std::filesystem::file_size(path/"data.mdb")<<std::endl;
  if(usage.ru_maxrss>1500000||std::filesystem::file_size(path/"data.mdb")>128ULL*1024*1024)throw std::runtime_error("isolated resource budget exceeded");
}
int main(int argc,char** argv){try{
  if(argc==4&&std::string(argv[1])=="--crash-child"){
    std::string path=argv[2],stage=argv[3];
    if(path.find("/home/privacydev/pc-v1-fixtures-rc4-")!=0||std::filesystem::exists(path)||(stage!="before_block_commit"&&stage!="after_block_commit"))throw std::runtime_error("isolated child arguments");
    Ledger ledger(path);auto t=ledger.mining_template(fresh(),wall_time()-120,fresh());auto raw=solve(ledger,t);crash_stage=stage;ledger.submit(raw);return 2;
  }
  if(argc!=2&&argc!=3)throw std::runtime_error("new absolute private fixture path required");
  const bool resume=argc==3&&std::string(argv[2])=="--resume-quiescent";
  const bool crash_only=argc==3&&std::string(argv[2])=="--crash-only";
  if(argc==3&&!resume&&!crash_only)throw std::runtime_error("unknown test option");
  std::filesystem::path root=argv[1];
  if(!root.is_absolute()||root.string().find("/home/privacydev/pc-v1-fixtures-rc4-")!=0||std::filesystem::exists(root))throw std::runtime_error("NEW_ISOLATED_PATH_REQUIRED");
  umask(0077);std::filesystem::create_directories(root);auto path=root/"chain";
  if(resume){std::filesystem::create_directories(path);std::filesystem::copy_file("/home/privacydev/pc-v1-fixtures-rc4-growth1/chain/data.mdb",path/"data.mdb");}
  const auto start=std::chrono::steady_clock::now();auto timestamp=wall_time()-10020*120;
  std::string tip;phase0::wide issued=0;std::vector<Template> branch;
  if(!resume&&!crash_only){
    Ledger ledger(path.string());
    for(uint64_t h=1;h<=10000;++h){
      auto t=ledger.mining_template(fresh(),timestamp+h*120,fresh());
      if(h>=9999)branch.push_back(t);
      auto expected=phase0::payout(issued,0);issued=phase0::add_issuance(issued,phase0::subsidy(issued));
      if(t.block.miner_tx.vout.front().amount!=expected||t.height!=h)throw std::runtime_error("reward or height mismatch");
      tip=ledger.submit(solve(ledger,t));
      if(ledger.tip().issued!=issued||ledger.tip().state.outputs.size()!=h)throw std::runtime_error("supply or output mismatch");
      if(h==1024||h==1025||h%1000==0)metrics(h,start,path);
      if(std::chrono::steady_clock::now()-start>std::chrono::minutes(30))throw std::runtime_error("growth deadline exceeded");
    }
    check(ledger.active_chain().size()==10001,"10000_real_pow_blocks_canonical_and_supply");
    branch.push_back(ledger.mining_template(fresh(),timestamp+10001*120,fresh()));
  }
  if(!crash_only){
    Ledger ledger(path.string());
    if(resume){
      tip=ledger.tip().id;for(uint64_t h=1;h<=10000;++h)issued=phase0::add_issuance(issued,phase0::subsidy(issued));
      auto chain=ledger.active_chain();
      for(auto h:{9999,10000}){auto e=ledger.get(chain.at(h));Template t{};t.block=e.block;t.height=e.height;t.difficulty=e.difficulty;auto seed=unhex(chain.at(phase0::seed_height(h)));std::memcpy(&t.seed,seed.data(),32);branch.push_back(t);}
      timestamp=ledger.tip().block.timestamp-10000*120;
      branch.push_back(ledger.mining_template(fresh(),timestamp+10001*120,fresh()));
    }
    check(ledger.tip().id==tip&&ledger.tip().height==10000&&ledger.tip().issued==issued,"restart_full_consensus_revalidation_10000");
    auto canonical=ledger.active_chain();
    for(uint64_t h=1;h<canonical.size();++h){auto e=ledger.get(canonical[h]);if(e.height!=h||e.parent!=canonical[h-1]||e.state.outputs[h-1].height!=h||e.state.outputs[h-1].index!=0||e.state.outputs[h-1].transaction!=hex(cryptonote::get_transaction_hash(e.block.miner_tx)))throw std::runtime_error("height output branch mapping");}
    check(true,"stable_height_output_index_mapping");
    std::string parent=canonical[9998];
    for(size_t i=0;i<branch.size();++i){auto t=branch[i];auto bytes=unhex(parent);std::memcpy(&t.block.prev_id,bytes.data(),32);
      boost::get<cryptonote::txout_to_key>(t.block.miner_tx.vout.front().target).key=fresh();
      parent=ledger.submit(solve(ledger,t));
      if(i<2&&ledger.tip().id!=tip)throw std::runtime_error("equal work must preserve original tip");
    }
    check(ledger.tip().height==10001&&ledger.tip().id==parent&&ledger.reorganizations==1&&ledger.disconnected==2,"fork_reorganization_beyond_10000");
    check(ledger.tip().state.outputs[9998].key!=ledger.get(canonical[9999]).state.outputs[9998].key,"fork_state_independence");
    tip=ledger.tip().id;metrics(10001,start,path);
  }
  if(!crash_only){Ledger ledger(path.string());check(ledger.tip().id==tip&&ledger.entries().size()==10004,"restart_preserves_canonical_and_forks");}
  for(const auto* stage:{"before_block_commit","after_block_commit"}){
    auto child_path=root/stage;auto child=fork();if(child<0)throw std::runtime_error("fork failed");
    // exec, as production does: never generate keys from a fork-inherited RNG.
    if(child==0){execl(argv[0],argv[0],"--crash-child",child_path.c_str(),stage,static_cast<char*>(nullptr));_exit(127);}
    int status=0;waitpid(child,&status,0);check(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL,"owned_child_interrupted_at_commit_boundary");
    Ledger ledger(child_path.string());check(ledger.tip().height==(std::string(stage)=="after_block_commit"?1:0),stage);
    auto t=ledger.mining_template(fresh(),wall_time(),fresh());ledger.submit(solve(ledger,t));check(ledger.tip().height>=1,"post_interruption_database_writable_and_valid");
  }
  std::cout<<(crash_only?"RESULT PASS_COMMIT_INTERRUPTION_ONLY_NOT_10000_RETEST":"RESULT PASS_ACTUAL_10000_BLOCK_GROWTH_NOT_TWO_HOST_OR_PUBLIC_NETWORK")<<std::endl;
  return 0;
}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<std::endl;return 1;}}
