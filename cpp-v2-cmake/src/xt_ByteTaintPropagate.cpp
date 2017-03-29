#include "xt_ByteTaintPropagate.h"

ByteTaintPropagate::ByteTaintPropagate(unsigned int addr) {
    taint_src_ = addr;
}

RangeArray *ByteTaintPropagate::get_taint_propagate() { return &range_array_; }
