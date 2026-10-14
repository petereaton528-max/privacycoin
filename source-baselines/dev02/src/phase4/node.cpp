// Local-only experimental private-spend node. No wallet secrets or mainnet.
#include "ledger.h"
#include <boost/asio.hpp>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <atomic>
#include <csignal>
#include <iostream>
#include <thread>
#include <set>
#include <fstream>
#include <boost/interprocess/sync/file_lock.hpp>

namespace pcdev {
namespace asio=boost::asio;
using tcp=asio::ip::tcp;
using Json=rapidjson::Document;
constexpr size_t frame_limit=1024*1024;
constexpr char rpc_magic[]="PrivacyCoinRPC04";
std::atomic<bool> stopping{false}, mining_stop{true}, mining_running{false};
std::atomic<uint64_t> mined{0}, mining_hashes{0};
std::string miner_error;
std::mutex error_mutex;
std::thread miner;
Json object() { Json d; d.SetObject(); return d; }
void put(Json& d,const char* name,const std::string& s) { d.AddMember(rapidjson::Value(name,d.GetAllocator()),rapidjson::Value(s.c_str(),static_cast<rapidjson::SizeType>(s.size()),d.GetAllocator()),d.GetAllocator()); }
void put(Json& d,const char* name,uint64_t v) { d.AddMember(rapidjson::Value(name,d.GetAllocator()),rapidjson::Value().SetUint64(v).Move(),d.GetAllocator()); }
std::string encode(const Json& d) { rapidjson::StringBuffer b; rapidjson::Writer<rapidjson::StringBuffer> w(b); d.Accept(w);return {b.GetString(),b.GetSize()}; }
Json decode(const std::string& s) {
  Json d; d.Parse<rapidjson::kParseIterativeFlag | rapidjson::kParseValidateEncodingFlag>(s.data(),s.size());
  if(d.HasParseError()||!d.IsObject()) throw std::runtime_error("malformed JSON request");
  std::set<std::string> keys;
  for(auto i=d.MemberBegin();i!=d.MemberEnd();++i) if(!keys.insert(i->name.GetString()).second) throw std::runtime_error("duplicate JSON member");
  return d;
}
std::string string(const Json& d,const char* name,const std::string& fallback="") {
  if(!d.HasMember(name)) return fallback;
  if(!d[name].IsString()) throw std::runtime_error(std::string("string required: ")+name);
  return {d[name].GetString(),d[name].GetStringLength()};
}
uint64_t number(const Json& d,const char* name,uint64_t fallback=0) {
  if(!d.HasMember(name)) return fallback;
  if(!d[name].IsUint64()) throw std::runtime_error(std::string("uint64 required: ")+name);
  return d[name].GetUint64();
}
void timeout(tcp::socket& s) {
  s.set_option(tcp::no_delay(true));
#ifdef _WIN32
  DWORD ms=5000;
  if(setsockopt(s.native_handle(),SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&ms),sizeof(ms))||
     setsockopt(s.native_handle(),SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&ms),sizeof(ms))) throw std::runtime_error("socket deadline configuration");
#else
  timeval tv{5,0};
  if(setsockopt(s.native_handle(),SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv))||setsockopt(s.native_handle(),SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv))) throw std::runtime_error("socket deadline configuration");
#endif
}
void send(tcp::socket& s,const std::string& magic,const std::string& body) {
  if(magic.size()!=16||body.size()>frame_limit) throw std::runtime_error("frame bounds");
  std::string header=magic;
  const uint32_t n=static_cast<uint32_t>(body.size());
  for(int shift=24;shift>=0;shift-=8) header+=char(n>>shift);
  asio::write(s,asio::buffer(header));asio::write(s,asio::buffer(body));
}
std::string receive(tcp::socket& s,const std::string& magic) {
  char header[20];asio::read(s,asio::buffer(header));
  if(std::string(header,16)!=magic) throw std::runtime_error("incompatible network magic");
  uint32_t n=0;for(int i=16;i<20;++i) n=(n<<8)|static_cast<unsigned char>(header[i]);
  if(n==0||n>frame_limit) throw std::runtime_error("frame bounds");
  std::string body(n,0);asio::read(s,asio::buffer(body));return body;
}
Json request(uint16_t port,Json& q) {
  asio::io_context io;tcp::socket s(io);
  s.connect({asio::ip::make_address("127.0.0.1"),port});timeout(s);
  send(s,network,encode(q)); auto d=decode(receive(s,network));
  if(string(d,"network")!=network||string(d,"genesis")!=genesis_id||string(d,"profile")!=identity) throw std::runtime_error("peer network/genesis/profile mismatch");
  if(d.HasMember("error")) throw std::runtime_error(string(d,"error"));
  return d;
}
void stop_miner() { mining_stop=true; if(miner.joinable()) miner.join(); mining_running=false; }
void start_miner(Ledger& l,const crypto::public_key& key,uint64_t count) {
  stop_miner(); mining_stop=false; mining_running=true;
  {std::lock_guard<std::mutex> lock(error_mutex);miner_error.clear();}
  miner=std::thread([&l,key,count] {
    uint64_t produced=0;
    try {
      while(!mining_stop&&!stopping&&(count==0||produced<count)) {
        auto t=l.mining_template(key); bool found=false;
        for(uint64_t nonce=0;nonce<=std::numeric_limits<uint32_t>::max()&&!mining_stop&&!stopping;++nonce) {
          t.block.nonce=static_cast<uint32_t>(nonce);
          const auto digest=l.hash(t.block,t.seed);++mining_hashes;
          if(phase0::pow_valid(digest,t.difficulty)) { found=true;break; }
          if(nonce%32==0 && hex(t.block.prev_id)!=l.tip().id) break;
        }
        if(found&&!mining_stop&&!stopping) {
          l.submit(cryptonote::block_to_blob(t.block),t.difficulty.convert_to<std::string>());
          ++produced;++mined;
        }
      }
    } catch(const std::exception& e) {std::lock_guard<std::mutex> lock(error_mutex);miner_error=e.what();}
    mining_running=false;
  });
}
Json handle(Ledger& l,const Json& q,bool p2p) {
  if(string(q,"network")!=network||string(q,"genesis")!=genesis_id||string(q,"profile")!=identity) throw std::runtime_error("incompatible network/genesis/profile");
  auto d=object();put(d,"network",network);put(d,"genesis",genesis_id);put(d,"profile",identity);
  const auto cmd=string(q,"command");
  if(p2p&&cmd!="inventory"&&cmd!="get_block"&&cmd!="status"&&cmd!="pool"&&cmd!="get_transaction") throw std::runtime_error("command unavailable on P2P");
  if(cmd=="status") {
    const auto e=l.tip();put(d,"height",e.height);put(d,"tip",e.id);put(d,"work",e.work.convert_to<std::string>());
    put(d,"difficulty",e.difficulty.convert_to<std::string>());
    put(d,"issued",e.issued.convert_to<std::string>());put(d,"hashes",l.hashes.load());put(d,"mined",mined.load());
    put(d,"mining_hashes",mining_hashes.load());
    put(d,"reorganizations",l.reorganizations.load());put(d,"disconnected",l.disconnected.load());
    put(d,"mining",uint64_t(mining_running.load()));
    d.AddMember("validation_ms",l.validation_ms.load(),d.GetAllocator());
    d.AddMember("transaction_validation_ms",l.transaction_validation_ms.load(),d.GetAllocator());put(d,"pool_expired",l.pool_expired.load());put(d,"pool_stale",l.pool_stale.load());
    std::lock_guard<std::mutex> lock(error_mutex);put(d,"mining_error",miner_error);
  } else if(cmd=="inventory") {
    auto locked=l.guard();auto all=l.entries();auto offset=number(q,"offset"),count=number(q,"count",1024);
    auto token=l.tip().id+"/"+std::to_string(all.size());
    if(count==0||count>1024||offset>all.size()||(!string(q,"cursor").empty()&&string(q,"cursor")!=token))throw std::runtime_error("inventory changed or page bounds");
    rapidjson::Value arr(rapidjson::kArrayType);
    auto end=std::min<uint64_t>(all.size(),offset+count);
    for(auto i=offset;i<end;++i) arr.PushBack(rapidjson::Value(all[i].id.c_str(),d.GetAllocator()),d.GetAllocator());
    d.AddMember("blocks",arr,d.GetAllocator());put(d,"next",end);put(d,"total",uint64_t(all.size()));put(d,"cursor",token);
  } else if(cmd=="get_block") {
    const auto e=l.get(string(q,"hash"));put(d,"block",hex(e.bytes.data(),e.bytes.size()));put(d,"height",e.height);
    put(d,"hash",e.id);put(d,"work",e.work.convert_to<std::string>());put(d,"difficulty",e.difficulty.convert_to<std::string>());
    put(d,"reward",e.height?e.block.miner_tx.vout.front().amount:0);
    auto cb=cryptonote::tx_to_blob(e.block.miner_tx);put(d,"coinbase",hex(cb.data(),cb.size()));
    rapidjson::Value txs(rapidjson::kArrayType);for(const auto& id:e.block.tx_hashes){auto raw=l.transaction(hex(id));auto h=hex(raw.data(),raw.size());txs.PushBack(rapidjson::Value(h.c_str(),d.GetAllocator()),d.GetAllocator());}d.AddMember("transactions",txs,d.GetAllocator());
  } else if(cmd=="chain") {
    auto locked=l.guard();auto tip=l.tip();auto chain=l.active_chain();auto offset=number(q,"offset"),count=number(q,"count",1024);
    if(count==0||count>1024||offset>chain.size()||(!string(q,"tip").empty()&&string(q,"tip")!=tip.id))throw std::runtime_error("chain changed or page bounds");
    rapidjson::Value ids(rapidjson::kArrayType),images(rapidjson::kArrayType);auto end=std::min<uint64_t>(chain.size(),offset+count);
    for(auto i=offset;i<end;++i)ids.PushBack(rapidjson::Value(chain[i].c_str(),d.GetAllocator()),d.GetAllocator());
    auto metadata_only=number(q,"metadata_only",0);if(metadata_only>1)throw std::runtime_error("metadata mode");
    if(!metadata_only)for(const auto& image:tip.state.images)images.PushBack(rapidjson::Value(image.c_str(),d.GetAllocator()),d.GetAllocator());
    d.AddMember("chain",ids,d.GetAllocator());d.AddMember("images",images,d.GetAllocator());put(d,"tip",tip.id);put(d,"height",tip.height);put(d,"next",end);put(d,"total",uint64_t(chain.size()));
  } else if(cmd=="history"||cmd=="pool_page"||cmd=="snapshot_id"||cmd=="orphan_images_page") {
    auto locked=l.guard();l.cleanup_pool();const auto current=l.tip();auto revision=l.pool_revision.load();
    if(!string(q,"tip").empty()&&(string(q,"tip")!=current.id||number(q,"revision")!=revision||string(q,"instance")!=l.instance))throw std::runtime_error("snapshot changed");
    put(d,"tip",current.id);put(d,"height",current.height);put(d,"revision",revision);put(d,"instance",l.instance);
    auto& allocator=d.GetAllocator();
    auto record=[&](const std::string& raw,uint64_t height,bool cb){
      cryptonote::transaction tx;if(!cryptonote::parse_and_validate_tx_from_blob(raw,tx))throw std::runtime_error("stored transaction parse");
      rapidjson::Value r(rapidjson::kObjectType),images(rapidjson::kArrayType);auto bytes=hex(raw.data(),raw.size()),id=hex(cryptonote::get_transaction_hash(tx));
      r.AddMember("transaction",rapidjson::Value(bytes.c_str(),allocator),allocator);r.AddMember("height",height,allocator);r.AddMember("coinbase",cb,allocator);r.AddMember("id",rapidjson::Value(id.c_str(),allocator),allocator);
      if(!cb)for(const auto& v:tx.vin)images.PushBack(rapidjson::Value(hex(boost::get<cryptonote::txin_to_key>(v).k_image).c_str(),allocator),allocator);
      r.AddMember("images",images,allocator);r.AddMember("fee",cb?uint64_t(0):tx.rct_signatures.txnFee,allocator);return r;
    };
    if(cmd=="history"){
      auto offset=number(q,"offset",1),count=number(q,"count",32);if(offset==0||count==0||count>32||offset>current.height+1)throw std::runtime_error("history page bounds");
      if(offset==1){rapidjson::Value images(rapidjson::kArrayType),orphan(rapidjson::kArrayType),pool(rapidjson::kArrayType);
        auto metadata_only=number(q,"metadata_only",0);if(metadata_only>1)throw std::runtime_error("metadata mode");
        if(!metadata_only){for(const auto& image:current.state.images)images.PushBack(rapidjson::Value(image.c_str(),allocator),allocator);
          for(const auto& image:l.orphan_images())orphan.PushBack(rapidjson::Value(image.c_str(),allocator),allocator);}
        d.AddMember("metadata_paged",bool(metadata_only),allocator);
        for(const auto& id:l.pool_inventory())pool.PushBack(rapidjson::Value(id.c_str(),allocator),allocator);
        d.AddMember("images",images,allocator);d.AddMember("orphan_images",orphan,allocator);d.AddMember("pool_ids",pool,allocator);}
      auto ids=l.active_chain();rapidjson::Value records(rapidjson::kArrayType);size_t budget=encode(d).size();uint64_t next=offset;
      while(next<ids.size()&&next<offset+count){auto block=l.get(ids[next]);auto cb=cryptonote::tx_to_blob(block.block.miner_tx);size_t size=cb.size()*2+256;
        for(const auto& id:block.block.tx_hashes)size+=l.transaction(hex(id)).size()*2+1024;
        if(budget+size>900000){if(next==offset)throw std::runtime_error("history response resource limit");break;}budget+=size;
        records.PushBack(record(cb,next,true),allocator);for(const auto& id:block.block.tx_hashes)records.PushBack(record(l.transaction(hex(id)),next,false),allocator);++next;
      }d.AddMember("records",records,allocator);put(d,"next",next);
    }else if(cmd=="orphan_images_page"){
      auto count=number(q,"count",1024);auto after=string(q,"after");
      if(count==0||count>1024||(!after.empty()&&(after.size()!=64||hex(unhex(after).data(),32)!=after)))throw std::runtime_error("image page bounds");
      auto page=l.orphan_images_after(after,count+1);bool done=page.size()<=count;if(!done)page.pop_back();
      rapidjson::Value images(rapidjson::kArrayType);for(const auto& image:page)images.PushBack(rapidjson::Value(image.c_str(),allocator),allocator);
      put(d,"after",page.empty()?after:page.back());d.AddMember("done",done,allocator);d.AddMember("images",images,allocator);
    }else if(cmd=="pool_page"){
      auto offset=number(q,"offset"),count=number(q,"count",8);auto pool=l.pool_entries();if(count==0||count>8||offset>pool.size())throw std::runtime_error("pool page bounds");
      rapidjson::Value entries(rapidjson::kArrayType);for(size_t i=offset;i<pool.size()&&i<offset+count;++i)entries.PushBack(record(pool[i].second,current.height+1,false),allocator);d.AddMember("entries",entries,allocator);
    }
  } else if(cmd=="get_transaction") {
    auto id=string(q,"hash");auto ids=l.pool_inventory();if(std::find(ids.begin(),ids.end(),id)==ids.end())throw std::runtime_error("unknown validated pool transaction");auto raw=l.transaction(id);put(d,"transaction",hex(raw.data(),raw.size()));
  } else if(cmd=="submit_tx") {
    put(d,"accepted",l.submit_transaction(unhex(string(q,"transaction"))));d.AddMember("validation_ms",l.transaction_validation_ms.load(),d.GetAllocator());d.AddMember("verify_ms",l.transaction_verify_ms.load(),d.GetAllocator());d.AddMember("commit_ms",l.pool_commit_ms.load(),d.GetAllocator());
  } else if(cmd=="pool") {
    rapidjson::Value ids(rapidjson::kArrayType);for(const auto& id:l.pool_inventory())ids.PushBack(rapidjson::Value(id.c_str(),d.GetAllocator()),d.GetAllocator());d.AddMember("transactions",ids,d.GetAllocator());
  } else if(cmd=="template") {
    auto t=l.mining_template(public_key(string(q,"reward_key")),number(q,"timestamp"),public_key(string(q,"R")));
    auto bytes=cryptonote::block_to_blob(t.block); auto blob=cryptonote::get_block_hashing_blob(t.block);
    put(d,"block",hex(bytes.data(),bytes.size()));put(d,"hashing_blob",hex(blob.data(),blob.size()));
    put(d,"difficulty",t.difficulty.convert_to<std::string>());put(d,"seed",hex(t.seed));put(d,"height",t.height);
    put(d,"timestamp",t.block.timestamp);put(d,"reward",t.block.miner_tx.vout.front().amount);
  } else if(cmd=="hash_benchmark") {
    auto count=number(q,"count",64);if(count==0||count>256)throw std::runtime_error("hash benchmark bounds");
    auto t=l.mining_template(public_key(string(q,"reward_key")),number(q,"timestamp"),public_key(string(q,"R")));auto began=std::chrono::steady_clock::now();
    for(uint64_t i=0;i<count;++i){t.block.nonce=uint32_t(i);l.hash(t.block,t.seed);}
    auto elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-began).count();d.AddMember("hashes_per_second",count/elapsed,d.GetAllocator());d.AddMember("seconds",elapsed,d.GetAllocator());put(d,"count",count);
  } else if(cmd=="mine") {
    auto t=l.mining_template(public_key(string(q,"reward_key")),number(q,"timestamp"),public_key(string(q,"R")));
    bool found=false;for(uint64_t nonce=0;nonce<=UINT32_MAX&&!stopping;++nonce){t.block.nonce=uint32_t(nonce);auto digest=l.hash(t.block,t.seed);fault("mining");if(phase0::pow_valid(digest,t.difficulty)){found=true;break;}}
    if(!found)throw std::runtime_error("mining interrupted");put(d,"accepted",l.submit(cryptonote::block_to_blob(t.block)));put(d,"height",t.height);
  } else if(cmd=="submit") {
    if(q.HasMember("transactions")){if(!q["transactions"].IsArray()||q["transactions"].Size()>8)throw std::runtime_error("transaction body count");for(const auto& tx:q["transactions"].GetArray()){if(!tx.IsString())throw std::runtime_error("transaction body type");l.import_transaction(unhex(tx.GetString()));}}
    put(d,"accepted",l.submit(unhex(string(q,"block")),string(q,"difficulty")));
  } else if(cmd=="start_mining") {
    throw std::runtime_error("Phase 4 requires fresh private reward outputs via mine");
  } else if(cmd=="stop_mining") {stop_miner();put(d,"stopped",uint64_t(1));
  } else if(cmd=="shutdown") {stopping=true;mining_stop=true;put(d,"stopping",uint64_t(1));
  } else throw std::runtime_error("unknown command");
  return d;
}
void serve(Ledger& l,uint16_t port,bool p2p,std::atomic<bool>& ready,std::string& failure) {
  try {
    asio::io_context io;tcp::acceptor a(io,{asio::ip::make_address("127.0.0.1"),port});ready=true;
    const std::string magic=p2p?network:rpc_magic;
    while(!stopping) {
      tcp::socket s(io);boost::system::error_code ec;bool accepted=false;
      // Wait for socket readiness instead of charging every request a polling
      // sleep. The bounded run interval still observes local shutdown promptly.
      a.async_accept(s,[&](const boost::system::error_code& result){ec=result;accepted=true;});
      while(!accepted&&!stopping){io.restart();io.run_for(std::chrono::milliseconds(10));}
      if(!accepted){a.cancel();io.restart();io.run();break;}
      if(ec) throw boost::system::system_error(ec);
      try {timeout(s);auto q=decode(receive(s,magic));auto d=handle(l,q,p2p);send(s,magic,encode(d));}
      catch(const std::exception& e) {
        try {auto d=object();put(d,"network",network);put(d,"genesis",genesis_id);put(d,"profile",identity);put(d,"error",e.what());send(s,magic,encode(d));} catch(...) {}
      }
    }
  } catch(const std::exception& e) { failure=e.what();stopping=true;ready=true; }
}
void peers(Ledger& l,uint16_t port) {
  while(!stopping) {
    try {
      auto q=object();put(q,"network",network);put(q,"genesis",genesis_id);put(q,"profile",identity);put(q,"command","inventory");
      uint64_t offset=0;std::string cursor;
      do{
      put(q,"offset",offset);if(!cursor.empty())put(q,"cursor",cursor);
      auto response=request(port,q);
      if(!response.HasMember("blocks")||!response["blocks"].IsArray()||response["blocks"].Size()>2048) throw std::runtime_error("invalid peer inventory");
      for(const auto& id:response["blocks"].GetArray()) {
        if(stopping) break;
        if(!id.IsString()||id.GetStringLength()!=64||unhex(id.GetString()).size()!=32) throw std::runtime_error("invalid peer block ID");
        bool exists=true;try {l.get(id.GetString());} catch(const std::out_of_range&) {exists=false;}
        if(exists) continue;
        auto bq=object();put(bq,"network",network);put(bq,"genesis",genesis_id);put(bq,"profile",identity);put(bq,"command","get_block");put(bq,"hash",id.GetString());
        auto block=request(port,bq);auto bytes=unhex(string(block,"block"));
        cryptonote::block parsed;
        if(!cryptonote::parse_and_validate_block_from_blob(bytes,parsed)||hex(cryptonote::get_block_hash(parsed))!=id.GetString()) throw std::runtime_error("peer block ID mismatch");
        if(!block.HasMember("transactions")||!block["transactions"].IsArray()||block["transactions"].Size()!=parsed.tx_hashes.size())throw std::runtime_error("peer transaction bodies");
        for(const auto& tx:block["transactions"].GetArray()){if(!tx.IsString())throw std::runtime_error("peer transaction type");l.import_transaction(unhex(tx.GetString()));}
        try {l.submit(bytes);} catch(const std::exception&) {try {l.get(id.GetString());}catch(...) {throw;}}
      }
      if(!response.HasMember("next"))break; // Older bounded peers.
      auto next=number(response,"next"),total=number(response,"total");
      if(next<=offset||next>total||next-offset!=response["blocks"].Size())throw std::runtime_error("invalid inventory page cursor");
      cursor=string(response,"cursor");offset=next;if(offset==total)break;
      q.RemoveMember("offset");q.RemoveMember("cursor");
      }while(!stopping);
      auto pq=object();put(pq,"network",network);put(pq,"genesis",genesis_id);put(pq,"profile",identity);put(pq,"command","pool");auto remote=request(port,pq);
      if(!remote.HasMember("transactions")||!remote["transactions"].IsArray()||remote["transactions"].Size()>32)throw std::runtime_error("invalid peer pool inventory");
      auto local=l.pool_inventory();
      for(const auto& id:remote["transactions"].GetArray()){
        if(!id.IsString()||id.GetStringLength()!=64)throw std::runtime_error("invalid peer transaction ID");std::string tid=id.GetString();if(std::find(local.begin(),local.end(),tid)!=local.end())continue;
        auto tq=object();put(tq,"network",network);put(tq,"genesis",genesis_id);put(tq,"profile",identity);put(tq,"command","get_transaction");put(tq,"hash",tid);auto tx=request(port,tq);auto raw=unhex(string(tx,"transaction"));
        cryptonote::transaction parsed;if(!cryptonote::parse_and_validate_tx_from_blob(raw,parsed)||hex(cryptonote::get_transaction_hash(parsed))!=tid)throw std::runtime_error("peer transaction ID mismatch");
        try{l.submit_transaction(raw);}catch(...){}
      }
    } catch(const std::exception& e) { if(!stopping) std::cerr<<"PEER: "<<e.what()<<"\n"; }
    for(int i=0;i<25&&!stopping;++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}
}
int main(int argc,char** argv) {
  using namespace pcdev;
  try {
    std::string directory,crash;uint16_t p2p=default_p2p_port,rpc=default_rpc_port;std::vector<uint16_t> peer_ports;uint64_t pool_ttl=3600;
    for(int i=1;i<argc;++i) {
      std::string arg=argv[i];if(i+1>=argc) throw std::runtime_error("missing option value");std::string value=argv[++i];
      if(arg=="--data-dir") directory=value;
      else if(arg=="--development-network") {
        if(value!="legacy-dev01"&&value!="open-dev02")throw std::runtime_error("unsupported development network; no Mainnet profile");
        network=value=="open-dev02"?"PrivacyCoinDev02":"PrivacyCoinDev01";
        identity=network+"/private-spend-v1-hardening/epoch18/"+genesis_id;
      }
      else if(arg=="--test-crash-stage")crash=value;
      else if(arg=="--pool-ttl"){size_t used=0;pool_ttl=std::stoull(value,&used);if(used!=value.size()||pool_ttl==0||pool_ttl>86400)throw std::runtime_error("pool TTL bounds");}
      else {size_t used=0;const auto n=std::stoul(value,&used);if(used!=value.size()||n==0||n>65535) throw std::runtime_error("port bounds");
        if(arg=="--p2p-port") p2p=static_cast<uint16_t>(n);else if(arg=="--rpc-port") rpc=static_cast<uint16_t>(n);else if(arg=="--peer-port") peer_ports.push_back(static_cast<uint16_t>(n));else throw std::runtime_error("unknown option");}
    }
    if(directory.empty()||p2p==rpc||std::find(peer_ports.begin(),peer_ports.end(),p2p)!=peer_ports.end()||peer_ports.size()>8) throw std::runtime_error("explicit separate data-dir and ports required");
    std::filesystem::create_directories(directory);
    const auto lockname=(std::filesystem::path(directory)/"node.lock").string();
    {std::ofstream file(lockname,std::ios::app);if(!file) throw std::runtime_error("data directory lock file");}
    boost::interprocess::file_lock directory_lock(lockname.c_str());
    if(!directory_lock.try_lock()) throw std::runtime_error("data directory already in use");
    Ledger ledger(directory,pool_ttl);crash_stage=crash;std::signal(SIGINT,[](int){stopping=true;mining_stop=true;});std::signal(SIGTERM,[](int){stopping=true;mining_stop=true;});
    std::atomic<bool> rpcready{false},p2pready{false};std::string rpcerror,p2perror;
    std::thread r([&]{serve(ledger,rpc,false,rpcready,rpcerror);});std::thread p([&]{serve(ledger,p2p,true,p2pready,p2perror);});std::vector<std::thread> sync;
    while(!rpcready||!p2pready) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if(!stopping)for(auto peer:peer_ports)sync.emplace_back([&,peer]{peers(ledger,peer);});
    if(!stopping) std::cout<<"READY "<<network<<" genesis="<<genesis_id<<" rpc="<<rpc<<" p2p="<<p2p<<std::endl;
    while(!stopping) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    mining_stop=true;r.join();p.join();stop_miner();for(auto& thread:sync)if(thread.joinable())thread.join();
    if(!rpcerror.empty()||!p2perror.empty()) throw std::runtime_error("listener: "+rpcerror+" "+p2perror);
    std::cout<<"STOPPED tip="<<ledger.tip().id<<std::endl;
  } catch(const std::exception& e) {std::cerr<<"FATAL: "<<e.what()<<std::endl;return 1;}
}
