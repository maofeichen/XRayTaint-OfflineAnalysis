#ifndef XT_TAINTPROPAGATE_H_
#define XT_TAINTPROPAGATE_H_

#include "xt_rangearray.h"

class TaintPropagate{
public:
  TaintPropagate(uint32_t taint_src) { taint_src_ = taint_src; }

  uint32_t get_src_addr() const { return taint_src_; }
  RangeArray* get_taint_propagate() { return &taint_prpgt_; }
private:
  uint32_t taint_src_;
  RangeArray taint_prpgt_;
};

#endif /* TAINTPROPAGATE_H_ */
