// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 petereaton528-max
#include "peer_budget.h"
#include <cassert>
int main(){
 using namespace pcdev;using namespace std::chrono;
 auto t=PeerBudget::clock::time_point{};PeerBudget b;
 assert(b.acquire(t));assert(!b.acquire(t+seconds(10)));
 b.finish(milliseconds(200),t);assert(!b.acquire(t+milliseconds(599)));assert(b.acquire(t+milliseconds(600)));
 b.finish(milliseconds(0),t);assert(!b.acquire(t+milliseconds(99)));assert(b.acquire(t+milliseconds(100)));
 PeerCooldown c;c.defer("a",t);for(int i=0;i<10000;++i)c.defer("a",t+seconds(59));
 assert(!c.eligible("a",t+seconds(59)));assert(c.eligible("a",t+seconds(60)));
 for(int i=0;i<1000;++i)c.defer(std::to_string(i),t);assert(c.size()==128);
 assert(c.eligible("new",t));assert(c.eligible("a",t+seconds(61)));assert(c.size()==0);
}
