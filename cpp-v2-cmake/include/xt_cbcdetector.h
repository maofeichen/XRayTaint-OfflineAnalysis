#ifndef XT_CBCDETECTOR_H
#define XT_CBCDETECTOR_H

#include "xt_blockmodedetector.h"

class CBCDetector : public BlockModeDetector{
 public:
  CBCDetector() {};

  bool analyze_mode(const RangeArray &in_blocks,
                    const VSPtrRangeArray &in_block_propa_ra,
                    const std::vector<ByteTaintPropagate *> &in_byte_propa);
};

#endif //XT_CBCDETECTOR_H
