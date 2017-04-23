#ifndef XT_BLOCKDETECTOR_H_
#define XT_BLOCKDETECTOR_H_

#include "xt_blockmodedetector.h"
#include "xt_taintpropagate.h"
#include <vector>

class BlockDetector{
public:
  BlockDetector(uint32_t in_begin, uint32_t in_len,
                uint32_t out_begin, uint32_t out_len);

  void detect_block(RangeArray      &in_blocks,
                    VSPtrRangeArray &in_blocks_prpgt,
                    const std::vector<TaintPropagate *>& in_prpgt_ra_res);
private:
  uint32_t in_begin_;
  uint32_t in_len_;
  uint32_t out_begin_;
  uint32_t out_len_;

  // For potential last block, we assume it is the last
  // We let the analyze function to determine if it is truely the last block
  void detect_block_not_handle_last(RangeArray      &in_blocks,
                                    VSPtrRangeArray &in_blocks_prpgt,
                                    const std::vector<TaintPropagate *>& in_prpgt_ra_res);

  // Returns the intersected propagated range (stores in common), given byte
  // a and byte b.
  bool init_block(RangeArray &common,
                  uint32_t idx_byte_a,
                  uint32_t idx_byte_b,
                  const std::vector<TaintPropagate *>& in_prpgt_ra_res);
  // Returns the intersected propagated range between the common and the
  // given byte
  bool extend_block(RangeArray &common,
                    uint32_t idx_byte,
                    const std::vector<TaintPropagate *>& in_prpgt_ra_res);
  bool save_block(RangeArray      &in_blocks,
                  VSPtrRangeArray &in_blocks_prpgt,
                  uint32_t        bk_begin_idx,
                  uint32_t        accumu_bk_sz,
                  RangeArray      &common);
  // Determines if a block ends by comparing previous accumulate common range,
  // with current byte accumulate common range
  bool is_block_end(RangeArray &common,
                    RangeArray &old_common,
                    uint32_t   accumu_b_sz);
};



#endif /* XT_BLOCKDETECTOR_H_ */
