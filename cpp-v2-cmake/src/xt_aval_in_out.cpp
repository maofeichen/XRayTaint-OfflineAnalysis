#include "xt_aval_in_out.h"
#include <iostream>
using namespace std;

Aval_In_Out::Aval_In_Out(t_AliveContinueBuffer &in,
                         t_AliveContinueBuffer &out) {
  in_.begin_addr = in.beginAddress;
  in_.sz_byte    = in.size / 8;
  for(auto it = in.vNodeIndex.begin(); it != in.vNodeIndex.end(); ++it) {
    v_src_index_.push_back(*it);
  }

  out_.begin_addr = out.beginAddress;
  out_.sz_byte    = out.size / 8;

  init();
}

void Aval_In_Out::init() {
  gen_in_propagated_byte();
}

void Aval_In_Out::gen_in_propagated_byte() {
  cout << "generating propagated byte arrays of input buffer..." << endl;

  if(v_src_index_.empty() ) {
    cout << "err: src index vector is empty" << endl;
    return;
  }

  uint32_t byte_pos   = 0;
  uint32_t begin_addr = in_.begin_addr;
  vector<uint32_t>::const_iterator it_src_idx = v_src_index_.begin();
  while (it_src_idx != v_src_index_.end() ) {
    // one byte in input may have multiple srcs, needs to know interval between
    // bytes
    uint32_t interval_multi_src;

  }
}