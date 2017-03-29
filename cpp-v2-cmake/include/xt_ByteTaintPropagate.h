#ifndef XT_BYTETAINTPROPAGATE_H_
#define XT_BYTETAINTPROPAGATE_H_

#include "RangeArray.h"

class ByteTaintPropagate {
 public:
  ByteTaintPropagate(unsigned int addr);
  ~ByteTaintPropagate() {};

  unsigned int get_taint_src() { return taint_src_; }
  RangeArray *get_taint_propagate();
 private:
  unsigned int taint_src_;
  RangeArray range_array_;
};

#endif /* XT_BYTETAINTPROPAGATE_H_ */
