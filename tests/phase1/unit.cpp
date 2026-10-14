#include "devnet/ledger.h"
#include <functional>
#include <iostream>

namespace pcdev {
void self_test() {
  unsigned checks=0;
  auto require=[&](bool ok,const char* name) {if(!ok) throw std::runtime_error(name);++checks;std::cout<<"PASS "<<name<<"\n";};
  auto rejects=[&](const std::function<void()>& f,const char* reason) {
    std::string error;try{f();}catch(const std::exception& e){error=e.what();}
    if(error.find(reason)==std::string::npos) std::cerr<<"Expected "<<reason<<"; actual: "<<error<<"\n";
    require(error.find(reason)!=std::string::npos,reason);
  };
  Ledger l;const auto key=public_key(reward_key);
  const auto magic=hex(network,16);
  require(magic!=hex(config::NETWORK_ID.data,16)&&magic!=hex(config::testnet::NETWORK_ID.data,16)&&magic!=hex(config::stagenet::NETWORK_ID.data,16),"identity differs from all pinned Monero network UUIDs");
  require(default_p2p_port==48080&&default_rpc_port==48081&&
    default_p2p_port!=config::P2P_DEFAULT_PORT&&default_p2p_port!=config::testnet::P2P_DEFAULT_PORT&&default_p2p_port!=config::stagenet::P2P_DEFAULT_PORT&&
    default_rpc_port!=config::RPC_DEFAULT_PORT&&default_rpc_port!=config::testnet::RPC_DEFAULT_PORT&&default_rpc_port!=config::stagenet::RPC_DEFAULT_PORT,"default ports differ from all pinned Monero network ports");
  require(l.tip().id==genesis_id,"frozen genesis ID");
  require(hex(l.tip().bytes.data(),l.tip().bytes.size())==genesis_bytes,"frozen canonical genesis bytes");
  require(l.tip().issued==0&&l.tip().work==0,"zero genesis allocation/work");
  auto t=l.mining_template(key,wall_time());
  require(t.difficulty==1&&t.height==1,"initial template difficulty/height");
  require(hex(t.seed)==genesis_id,"bootstrap RandomX key");
  const auto original=cryptonote::block_to_blob(t.block);
  auto mutate=[&](const std::function<void(cryptonote::block&)>& f,const char* error) {
    auto b=t.block;f(b);rejects([&]{l.submit(cryptonote::block_to_blob(b));},error);
  };
  mutate([](auto& b){b.prev_id=crypto::null_hash;},"previous");
  mutate([](auto& b){boost::get<cryptonote::txin_gen>(b.miner_tx.vin.front()).height=2;},"coinbase height");
  mutate([](auto& b){++b.miner_tx.vout.front().amount;},"subsidy/fee");
  mutate([](auto& b){--b.miner_tx.vout.front().amount;},"subsidy/fee");
  mutate([](auto& b){b.miner_tx.unlock_time=60;},"maturity");
  mutate([](auto& b){b.timestamp=wall_time()+7201;},"future");
  mutate([](auto& b){b.major_version=1;},"version");
  mutate([](auto& b){b.tx_hashes.push_back(crypto::null_hash);},"ordinary transactions");
  mutate([](auto& b){b.miner_tx.vout.push_back(b.miner_tx.vout.front());},"outputs");
  mutate([](auto& b){b.miner_tx.extra.push_back(0);},"domain/extra");
  rejects([&]{l.submit(original,"2");},"difficulty");
  rejects([&]{l.submit(original,"01");},"difficulty");
  rejects([&]{l.submit(std::string(300001,'x'));},"size/weight");
  rejects([&]{l.submit("\xff\xff");},"malformed");
  rejects([&]{l.submit(original+std::string(1,'\0'));},"block");
  rejects([&]{public_key(std::string(64,'0'));},"key");
  rejects([&]{public_key("01"+std::string(62,'0'));},"identity");
  const auto h1=l.submit(original,"1");
  require(l.tip().height==1&&l.tip().work==1&&l.tip().issued==35184372088831ULL,"accepted real RandomX coinbase");
  require(l.tip().block.miner_tx.vout.front().amount==35184372088831ULL,"first subsidy");
  rejects([&]{l.submit(original);},"duplicate");
  auto t2=l.mining_template(key,t.block.timestamp);
  require(t2.difficulty==1,"bootstrap second difficulty");
  l.submit(cryptonote::block_to_blob(t2.block));
  auto t3=l.mining_template(key,t.block.timestamp);
  require(t3.difficulty==120,"equal timestamp retarget is real DAA");
  uint64_t tries=0;bool valid=false;
  while(tries<10000) {
    t3.block.nonce=static_cast<uint32_t>(tries++);
    valid=phase0::pow_valid(l.hash(t3.block,t3.seed),t3.difficulty);
    if(!valid) {rejects([&]{l.submit(cryptonote::block_to_blob(t3.block));},"RandomX PoW");break;}
  }
  require(!valid,"actual invalid RandomX nonce found");
  for(;tries<10000;++tries) {t3.block.nonce=static_cast<uint32_t>(tries);if(phase0::pow_valid(l.hash(t3.block,t3.seed),t3.difficulty)){valid=true;break;}}
  require(valid,"CPU nonce search at retargeted difficulty");
  l.submit(cryptonote::block_to_blob(t3.block),"120");
  require(l.tip().work==122,"cumulative work includes retargeted block");
  Ledger longer;
  for(unsigned i=0;i<5;++i) {auto candidate=longer.mining_template(key,t.block.timestamp+i*120);longer.submit(cryptonote::block_to_blob(candidate.block));}
  require(longer.tip().height==5&&longer.tip().work==5,"longer low-work competing chain");
  for(const auto& e:l.entries()) if(e.height) {try {longer.get(e.id);}catch(const std::out_of_range&) {longer.submit(e.bytes);}}
  require(longer.tip().height==3&&longer.tip().work==122&&longer.reorganizations==1,"shorter greater-work chain wins over longer chain");
  auto t4=l.mining_template(key,t.block.timestamp);
  auto b=t4.block;b.timestamp=t.block.timestamp-1;
  rejects([&]{l.submit(cryptonote::block_to_blob(b));},"below median");
  Ledger fork;
  auto a=fork.mining_template(key,wall_time());
  auto competing=a.block;competing.nonce=1;
  const auto first=fork.submit(cryptonote::block_to_blob(a.block));
  const auto second=fork.submit(cryptonote::block_to_blob(competing));
  require(fork.tip().id==first&&first!=second,"equal-work branch retains current tip");
  Ledger branch;branch.submit(cryptonote::block_to_blob(competing));
  auto child=branch.mining_template(key,competing.timestamp+120);
  fork.submit(cryptonote::block_to_blob(child.block));
  require(fork.tip().height==2&&fork.reorganizations==1&&fork.disconnected==1,"greater-work reorg disconnects one block");
  require(fork.get(first).height==1&&fork.active_chain()[1]==second,"disconnected branch retained but inactive");
  auto blob=cryptonote::get_block_hashing_blob(a.block);++a.block.nonce;
  require(blob!=cryptonote::get_block_hashing_blob(a.block),"canonical template commits nonce");
  require(!phase0::mature(1,60)&&phase0::mature(1,61),"coinbase maturity 60-block boundary");
  require(phase0::payout(0,123)==35184372088954ULL,"nonzero fee adapter accounting (not transaction support)");
  require(phase0::difficulty({0,120},{1,2})==1&&phase0::difficulty({42,42},{1,2})==120,"deterministic DAA normal/pathological vectors");
  require(phase0::seed_height(2112)==0&&phase0::seed_height(2113)==2048,"seed epoch boundary");
  {
    Ledger window;
    std::string epoch_block,first_bytes,first_blob,first_digest;
    for(uint64_t h=1;h<=2113;++h) {
      auto candidate=window.mining_template(key,h*120);
      if(h==1) {
        auto bytes=cryptonote::block_to_blob(candidate.block);auto blob=cryptonote::get_block_hashing_blob(candidate.block);
        first_bytes=hex(bytes.data(),bytes.size());first_blob=hex(blob.data(),blob.size());first_digest=hex(window.hash(candidate.block,candidate.seed));
      }
      require(candidate.difficulty==1,"target-spaced ancestry DAA");
      if(h==736) require(window.tip().height==735,"full DAA window uses actual block ancestry");
      if(h==2112) require(hex(candidate.seed)==genesis_id,"last actual bootstrap seed template");
      if(h==2113) require(hex(candidate.seed)==epoch_block&&epoch_block!=genesis_id,"actual branch-derived 2048 seed at height 2113");
      const auto accepted=window.submit(cryptonote::block_to_blob(candidate.block));
      if(h==2048) epoch_block=accepted;
    }
    require(window.tip().height==2113&&window.tip().work==2113,"real RandomX validation across seed-cache replacement");
    std::cout<<"VECTOR {\"height_1_block\":\""<<first_bytes<<"\",\"height_1_hashing_blob\":\""<<first_blob
      <<"\",\"height_1_randomx\":\""<<first_digest<<"\",\"height_2048_hash\":\""<<epoch_block
      <<"\",\"height_2113_hash\":\""<<window.tip().id<<"\",\"height_2113_work\":\""<<window.tip().work<<"\"}\n";
  }
  const auto path=(std::filesystem::current_path()/"devnet-data"/("unit-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))).string();
  std::string persisted;
  {Ledger disk(path); auto candidate=disk.mining_template(key);persisted=disk.submit(cryptonote::block_to_blob(candidate.block));}
  {Ledger disk(path);require(disk.tip().id==persisted,"LMDB round-trip validation");}
  auto corrupt=[&](const std::string& k,const std::string& value) {
    MDB_env* env=nullptr;MDB_txn* tx=nullptr;MDB_dbi dbi;
    require(mdb_env_create(&env)==0,"fixture LMDB environment");
    require(mdb_env_open(env,path.c_str(),MDB_NOTLS,0600)==0,"fixture LMDB open");
    require(mdb_txn_begin(env,nullptr,0,&tx)==0&&mdb_dbi_open(tx,nullptr,0,&dbi)==0,"fixture LMDB transaction");
    MDB_val mk{k.size(),const_cast<char*>(k.data())},mv{value.size(),const_cast<char*>(value.data())};
    require(mdb_put(tx,dbi,&mk,&mv,0)==0&&mdb_txn_commit(tx)==0,"fixture LMDB alteration");mdb_env_close(env);
  };
  corrupt("identity","Monero/wrong-genesis");
  rejects([&]{Ledger disk(path);},"incompatible network/genesis");
  corrupt("identity",identity);corrupt("b:"+persisted,"corrupt serialized block");
  rejects([&]{Ledger disk(path);},"corrupt persisted block");
  std::cout<<"PASS "<<checks<<" Phase 1 implementation-linked checks\n";
}
}
