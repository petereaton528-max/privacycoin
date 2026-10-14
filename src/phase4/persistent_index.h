// In-memory branch indexes. Immutable AVL nodes share unchanged subtrees;
// copying an index is O(1), insertion/lookup O(log n). Not serialized or consensus.
#pragma once
#include <algorithm>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace pcdev {
template<class K, class V> class BranchIndex {
  struct Node;
  using Ptr = std::shared_ptr<const Node>;
  struct Node {
    K key; V value; Ptr left, right; int height;
    Node(K k, V v, Ptr l, Ptr r):key(std::move(k)),value(std::move(v)),left(std::move(l)),right(std::move(r)),
      height(1+std::max(h(left),h(right))) {}
  };
  Ptr root;
  size_t length=0;
  static int h(const Ptr& p) { return p?p->height:0; }
  static Ptr make(const K& k,const V& v,Ptr l,Ptr r) { return std::make_shared<Node>(k,v,std::move(l),std::move(r)); }
  static Ptr balance(const K& k,const V& v,Ptr l,Ptr r) {
    if(h(l)>h(r)+1) {
      if(h(l->right)>h(l->left)) {
        auto m=l->right;
        l=make(m->key,m->value,make(l->key,l->value,l->left,m->left),m->right);
      }
      return make(l->key,l->value,l->left,make(k,v,l->right,r));
    }
    if(h(r)>h(l)+1) {
      if(h(r->left)>h(r->right)) {
        auto m=r->left;
        r=make(m->key,m->value,m->left,make(r->key,r->value,m->right,r->right));
      }
      return make(r->key,r->value,make(k,v,l,r->left),r->right);
    }
    return make(k,v,std::move(l),std::move(r));
  }
  static Ptr add(const Ptr& p,const K& k,const V& v) {
    if(!p)return make(k,v,nullptr,nullptr);
    if(k<p->key)return balance(p->key,p->value,add(p->left,k,v),p->right);
    return balance(p->key,p->value,p->left,add(p->right,k,v));
  }
 public:
  const V* find(const K& key) const {
    auto p=root.get();while(p){if(key==p->key)return &p->value;p=(key<p->key?p->left:p->right).get();}return nullptr;
  }
  size_t count(const K& key) const { return find(key)?1:0; }
  size_t size() const { return length; }
  bool insert(const K& key,const V& value) {
    if(find(key))return false;
    auto replacement=add(root,key,value);root=std::move(replacement);++length;return true;
  }
  class iterator {
    Ptr owner; std::vector<const Node*> path;
    void descend(const Node* p){while(p){path.push_back(p);p=p->left.get();}}
   public:
    explicit iterator(Ptr p=nullptr):owner(std::move(p)){descend(owner.get());}
    const K& operator*()const{return path.back()->key;}
    iterator& operator++(){auto p=path.back();path.pop_back();descend(p->right.get());return *this;}
    bool operator!=(const iterator& other)const{return (path.empty()?nullptr:path.back())!=(other.path.empty()?nullptr:other.path.back());}
  };
  iterator begin()const{return iterator(root);} iterator end()const{return iterator();}
};
template<class K> class BranchSet:public BranchIndex<K,bool> {
 public:
  std::pair<bool,bool> insert(const K& key){auto added=BranchIndex<K,bool>::insert(key,true);return {added,added};}
  template<class I> void insert(I a,I b){for(;a!=b;++a)insert(*a);}
};
template<class V> class BranchVector:private BranchIndex<uint64_t,V> {
 public:
  using BranchIndex<uint64_t,V>::size;
  void push_back(const V& value){BranchIndex<uint64_t,V>::insert(size(),value);}
  const V& operator[](uint64_t index)const{auto p=BranchIndex<uint64_t,V>::find(index);if(!p)throw std::out_of_range("branch output index");return *p;}
};
}
