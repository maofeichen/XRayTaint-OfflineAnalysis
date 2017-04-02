// ! Currently not use
// Maintains data during avalanche detection: block detection, mode detection,
// etc
#ifndef XT_AVAL_IN_OUT_H
#define XT_AVAL_IN_OUT_H
#include "xt_data.h"

class Aval_In_Out{
 public:
  Aval_In_Out(t_AliveContinueBuffer &in, t_AliveContinueBuffer &out);
 private:
  struct Buf_{
    uint32_t begin_addr;
    uint32_t sz_byte; // pass 1 more byte than the size of the buffer
  };

  struct Propagate_Byte_ {
    uint32_t addr;
    std::string val;

    bool operator<(const Propagate_Byte_ &propagate_byte) const {
      return (addr < propagate_byte.addr);
    }
  };

  Buf_ in_;
  Buf_ out_;
  std::vector<uint32_t> v_src_index_;

  std::vector<std::vector<Aval_In_Out::Propagate_Byte_> > v_in_propa_byte_;

  void init();
  void gen_in_propagated_byte();
};
#endif //XT_AVAL_IN_OUT_H
