#include "xt_contbuf.h"
#include <iostream>
#include <vector>

using namespace std;

ContinueBuf::ContinueBuf(const ContinueBuf &rhs)
{
  begin_addr_ = rhs.begin_addr_;
  byte_sz_    = rhs.byte_sz_;
  for(auto it = rhs.v_node_idx_.begin(); it != rhs.v_node_idx_.end(); ++it) {
    v_node_idx_.push_back(*it);
  }
}

ContinueBuf&
ContinueBuf::operator=(const ContinueBuf &rhs)
{
  begin_addr_ = rhs.begin_addr_;
  byte_sz_    = rhs.byte_sz_;
  for(auto it = rhs.v_node_idx_.begin(); it != rhs.v_node_idx_.end(); ++it) {
    v_node_idx_.push_back(*it);
  }
  return *this;
}

void
ContinueBuf::add_node_idx(const uint32_t node_idx)
{
  v_node_idx_.push_back(node_idx);
}

void
ContinueBuf::set_node_idx(const std::vector<uint32_t> &v_node_idx)
{
  for(auto it = v_node_idx.begin(); it != v_node_idx.end(); ++it) {
    v_node_idx_.push_back(*it);
  }
}


void
ContinueBuf::clear_node_idx()
{
  std::vector<uint32_t> v_swp;
  v_node_idx_.swap(v_swp);
}

void ContinueBuf::print_cont_buf() const
{
  cout << "begin addr: " << hex << begin_addr_ << endl;
  cout << "byte sz: "    << dec << byte_sz_ << endl;
  for(auto it = v_node_idx_.begin(); it != v_node_idx_.end(); ++it) {
    cout << "node idx: " << *it << endl;
  }
}

void ContinueBuf::print_cont_buf_noidx() const
{
  cout << "begin addr: " << hex << begin_addr_ << endl;
  cout << "byte sz: "    << dec << byte_sz_ << endl;
}

