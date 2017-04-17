#ifndef XT_DATA_H_
#define XT_DATA_H_

#include "xt_node.h"
#include <vector>

struct Cont_Buf_{
  uint32_t begin_addr = 0;
  uint32_t byte_sz    = 0;
  std::vector<uint32_t> v_node_idx;
};

struct Alive_Func_{
  Node fir_c_mark;
  Node sec_c_mark;
  Node fir_r_mark;
  Node sec_r_mark;
  std::vector<Cont_Buf_> v_cont_buf;

  Alive_Func_() {}
  Alive_Func_(const Alive_Func_& rhs) {
    fir_c_mark = rhs.fir_c_mark;
    sec_c_mark = rhs.sec_c_mark;
    fir_r_mark = rhs.fir_r_mark;
    sec_r_mark = rhs.sec_r_mark;
    for(auto it = rhs.v_cont_buf.begin(); it != rhs.v_cont_buf.end(); ++it) {
      v_cont_buf.push_back(*it);
    }
  }
};

#endif /* XT_DATA_H_ */
