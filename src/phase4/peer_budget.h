// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 petereaton528-max
#pragma once
#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <algorithm>
namespace pcdev {
// Relay policy only. Never used by historical/block consensus validation.
class PeerBudget {
 public:
  using clock=std::chrono::steady_clock;
  bool acquire(clock::time_point now=clock::now()) {
    std::lock_guard<std::mutex> lock(mutex);
    if(busy||now<next)return false;
    busy=true;return true;
  }
  void finish(clock::duration elapsed,clock::time_point now=clock::now()) {
    std::lock_guard<std::mutex> lock(mutex);
    // At most one remote validation job at once; at least 3x measured idle
    // time between jobs. This bounds duty cycle, not single-proof latency.
    next=now+std::max(clock::duration(std::chrono::milliseconds(100)),elapsed*3);busy=false;
  }
 private:
  std::mutex mutex;bool busy=false;clock::time_point next{};
};
class PeerCooldown {
 public:
  using clock=std::chrono::steady_clock;
  bool eligible(const std::string& id,clock::time_point now=clock::now()) {
    for(auto i=until.begin();i!=until.end();)if(i->second<=now)i=until.erase(i);else ++i;
    return !until.count(id);
  }
  void defer(const std::string& id,clock::time_point now=clock::now()) {
    if(until.count(id))return; // rejected traffic cannot extend its deadline
    if(until.size()>=128)until.erase(std::min_element(until.begin(),until.end(),[](auto&a,auto&b){return a.second<b.second;}));
    until.emplace(id,now+std::chrono::seconds(60));
  }
  size_t size()const{return until.size();}
 private:std::map<std::string,clock::time_point> until;
};
}
