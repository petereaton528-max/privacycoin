// Isolated research adapter, never linked into a node or the normal wallet.
// Reuse pinned primitives and pipe utilities; frozen adapter is byte unchanged.
#define main phase4_unused_entry
#include "../phase4/crypto.cpp"
#undef main
#include <sstream>

std::string base_blob(transaction& tx) {
  std::ostringstream stream; binary_archive<true> archive(stream);
  need(tx.serialize_base(archive)); return stream.str();
}

void process(rapidjson::Document& q, rapidjson::Document& out) {
  auto& a=out.GetAllocator(); auto op=std::string(q["op"].GetString());
  need(op=="project"||op=="verify"||op=="scan"||op=="empty");
  if(op=="empty")return;
  const bool project=op=="project",verify=op=="verify";
  account_keys keys{}; auto& device=hw::get_device("default");
  std::unordered_map<crypto::public_key,subaddress_index> addresses;
  bool full=false;
  if(!project&&!verify){
    keys.m_view_secret_key=read<crypto::secret_key>(q["view"]);
    keys.m_account_address.m_spend_public_key=read<crypto::public_key>(q["public"]);point(keys.m_account_address.m_spend_public_key);
    need(crypto::secret_key_to_public_key(keys.m_view_secret_key,keys.m_account_address.m_view_public_key));
    full=q.HasMember("spend");if(full){keys.m_spend_secret_key=read<crypto::secret_key>(q["spend"]);crypto::public_key B;
      need(crypto::secret_key_to_public_key(keys.m_spend_secret_key,B)&&B==keys.m_account_address.m_spend_public_key);}
    auto count=q["count"].GetUint();need(count>0&&count<=10000);
    for(uint32_t i=0;i<count;++i)addresses.emplace(device.get_subaddress_spend_public_key(keys,{0,i}),subaddress_index{0,i});
  }
  std::set<std::string> spent,reserved;
  if(q.HasMember("images"))for(const auto& v:q["images"].GetArray())spent.insert(v.GetString());
  if(q.HasMember("pool_images"))for(const auto& v:q["pool_images"].GetArray())reserved.insert(v.GetString());
  J owned(rapidjson::kArrayType),eligible(rapidjson::kArrayType),records(rapidjson::kArrayType),images(rapidjson::kArrayType);
  uint64_t global=q.HasMember("offset")?q["offset"].GetUint64():0,scanned=0,undecodable=0;
  auto begin=started();
  for(const auto& record:q["chain"].GetArray()){
    transaction tx;auto raw=uh(record["transaction"].GetString());crypto::hash id;
    const bool pruned=record.HasMember("prunable_hash");
    if(pruned){need(parse_and_validate_tx_base_from_blob(raw,tx,true,true)&&base_blob(tx)==raw);
      auto hash=read<crypto::hash>(record["prunable_hash"]);need(get_pruned_transaction_hash(tx,hash,id));}
    else{need(parse_and_validate_tx_from_blob(raw,tx)&&tx_to_blob(tx)==raw);id=get_transaction_hash(tx);}
    need(tx.version==2);const bool cb=tx.vin.size()==1&&tx.vin[0].type()==typeid(txin_gen);
    need(cb==record["coinbase"].GetBool());auto height=record["height"].GetUint64();
    need(cb?tx.rct_signatures.type==rct::RCTTypeNull:tx.rct_signatures.type==rct::RCTTypeBulletproofPlus);
    if(cb)need(boost::get<txin_gen>(tx.vin[0]).height==height);
    if(record.HasMember("id"))need(hx(id)==record["id"].GetString());
    for(const auto& input:tx.vin)if(input.type()==typeid(txin_to_key))images.PushBack(J(hx(boost::get<txin_to_key>(input).k_image).c_str(),a),a);
    if(verify)continue;
    if(project){
      need(!pruned);auto hash=cb?crypto::null_hash:get_transaction_prunable_hash(tx);auto blob=base_blob(tx);
      J v(rapidjson::kObjectType);v.AddMember("transaction",J(hx(blob.data(),blob.size()).c_str(),a),a);
      v.AddMember("prunable_hash",J(hx(hash).c_str(),a),a);v.AddMember("id",J(hx(id).c_str(),a),a);
      v.AddMember("height",height,a);v.AddMember("coinbase",cb,a);records.PushBack(v,a);continue;
    }
    const auto R=get_tx_pub_key_from_extra(tx);point(R);auto additional=get_additional_tx_pub_keys_from_extra(tx);
    need(additional.empty()||additional.size()==tx.vout.size());
    crypto::key_derivation primary;need(crypto::generate_key_derivation(R,keys.m_view_secret_key,primary));
    for(size_t i=0;i<tx.vout.size();++i,++global,++scanned){
      auto P=boost::get<txout_to_key>(tx.vout[i].target).key;point(P);
      auto unlock=height+(cb?60:10);if(unlock<=q["height"].GetUint64()+1)eligible.PushBack(global,a);
      for(unsigned choice=0;choice<(additional.empty()?1:2);++choice){
        auto d=primary;if(choice)need(crypto::generate_key_derivation(additional[i],keys.m_view_secret_key,d));
        crypto::public_key D;need(crypto::derive_subaddress_public_key(P,d,i,D));auto found=addresses.find(D);if(found==addresses.end())continue;
        uint64_t amount=tx.vout[i].amount;rct::key mask;
        if(!cb){crypto::ec_scalar scalar;crypto::derivation_to_scalar(d,i,scalar);rct::key amountkey;memcpy(&amountkey,&scalar,32);
          try{amount=rct::decodeRctSimple(tx.rct_signatures,amountkey,i,mask,device);}catch(...){++undecodable;break;}}
        crypto::key_image image{};if(full){keypair ephemeral;need(generate_key_image_helper(keys,addresses,P,R,additional,i,ephemeral,image,device));}
        J v(rapidjson::kObjectType);v.AddMember("global_index",global,a);v.AddMember("amount",amount,a);v.AddMember("height",height,a);
        v.AddMember("unlock",unlock,a);v.AddMember("spent",full?J(bool(spent.count(hx(image)))):J(rapidjson::kNullType),a);
        v.AddMember("reserved",full?J(bool(reserved.count(hx(image)))):J(rapidjson::kNullType),a);v.AddMember("pending",false,a);
        v.AddMember("coinbase",cb,a);v.AddMember("address_index",found->second.minor,a);v.AddMember("output_index",uint64_t(i),a);
        v.AddMember("transaction",J(hx(id).c_str(),a),a);if(full)v.AddMember("image",J(hx(image).c_str(),a),a);owned.PushBack(v,a);break;
      }
    }
  }
  out.AddMember("scan_ms",ms(begin),a);out.AddMember("scanned_outputs",scanned,a);out.AddMember("undecodable_owned_outputs",undecodable,a);
  out.AddMember("owned",owned,a);out.AddMember("eligible",eligible,a);out.AddMember("chain",records,a);out.AddMember("images",images,a);
  sodium_memzero(&keys.m_view_secret_key,sizeof(keys.m_view_secret_key));sodium_memzero(&keys.m_spend_secret_key,sizeof(keys.m_spend_secret_key));
}

int main(int argc,char** argv){
  // Strong CPU baseline: same frozen scanner in the same persistent pipe
  // lifecycle. The reference body above is included without byte edits.
  if(argc==2&&std::string(argv[1])=="--reference"){
    while(std::cin.peek()!=EOF){int result=phase4_unused_entry();std::cout.flush();if(result)return result;}return 0;
  }
  if(argc!=1)return 1;
  if(sodium_init()<0)return 1;
  std::string line;
  while(std::getline(std::cin,line)){
    try{
      need(line.size()<32*1024*1024);rapidjson::Document q;q.Parse(line.c_str());need(q.IsObject()&&q.HasMember("op")&&q["op"].IsString());
      rapidjson::Document out;out.SetObject();process(q,out);
      rapidjson::StringBuffer buffer;rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);out.Accept(writer);std::cout<<buffer.GetString()<<std::endl;
      sodium_memzero(line.data(),line.size());
    }catch(...){sodium_memzero(line.data(),line.size());std::cerr<<"research request rejected\n";return 1;}
  }
  return 0;
}
