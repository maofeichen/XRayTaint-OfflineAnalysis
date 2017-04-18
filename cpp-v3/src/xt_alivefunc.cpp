#include "xt_alivefunc.h"
#include <iostream>
#include <vector>

using namespace std;

AliveFunction::AliveFunction(const AliveFunction &rhs)
{
  fir_c_mark_ = rhs.fir_c_mark_;
  sec_c_mark_ = rhs.sec_c_mark_;
  fir_r_mark_ = rhs.fir_r_mark_;
  sec_r_mark_ = rhs.sec_r_mark_;
  for (auto it = rhs.v_continuebuf_.begin(); it != rhs.v_continuebuf_.end(); ++it) {
    v_continuebuf_.push_back(*it);
  }
}

AliveFunction&
AliveFunction::operator=(const AliveFunction &rhs)
{
  fir_c_mark_ = rhs.fir_c_mark_;
  sec_c_mark_ = rhs.sec_c_mark_;
  fir_r_mark_ = rhs.fir_r_mark_;
  sec_r_mark_ = rhs.sec_r_mark_;
  for (auto it = rhs.v_continuebuf_.begin(); it != rhs.v_continuebuf_.end(); ++it) {
    v_continuebuf_.push_back(*it);
  }
  return *this;
}


void
AliveFunction::add_cont_buf(const ContinueBuf& continuebuf)
{
  v_continuebuf_.push_back(continuebuf);
}

void
AliveFunction::rm_cont_buf_less(const uint32_t byte_sz)
{
  vector<ContinueBuf> v_swap;
  for(auto it = v_continuebuf_.begin(); it != v_continuebuf_.end(); ++it) {
    if(it->get_byte_sz() >= byte_sz) {
      v_swap.push_back(*it);
    }
  }
  v_continuebuf_.swap(v_swap);
}

void
AliveFunction::rm_cont_buf_large_addr(const uint32_t addr)
{
  vector<ContinueBuf> v_swap;
  for(auto it = v_continuebuf_.begin(); it != v_continuebuf_.end(); ++it) {
    if(it->get_begin() < addr) {
      v_swap.push_back(*it);
    }
  }
  v_continuebuf_.swap(v_swap);
//  for(auto it = v_continuebuf_.begin(); it != v_continuebuf_.end(); ) {
//    if(it->get_byte_sz() >= byte_sz) {
//      v_continuebuf_.erase(it);
//    } else {
//      ++it;
//    }
//  }
}

void AliveFunction::print_alive_func() const
{
  cout << "alive function call: " << endl;
  fir_c_mark_.print_node();
  sec_c_mark_.print_node();
  fir_r_mark_.print_node();
  sec_r_mark_.print_node();

  cout << "num of continuous buf: " << v_continuebuf_.size() << endl;
  for(auto it = v_continuebuf_.begin(); it != v_continuebuf_.end(); ++it) {
    it->print_cont_buf();
  }
}
