#ifndef XT_CBCDETECTOR_H
#define XT_CBCDETECTOR_H

#include "xt_blockmodedetector.h"

class CBCDetector : public BlockModeDetector{
 public:
  CBCDetector() {};
  CBCDetector(uint32_t output_begin, uint32_t output_sz);

  bool analyze_mode(const RangeArray &in_blocks,
                    const VSPtrRangeArray &in_block_propa_ra,
                    const std::vector<ByteTaintPropagate *> &in_byte_propa);
 private:
  uint32_t output_begin_ = 0;
  uint32_t output_sz_    = 0;

  bool analyze_enc(const RangeArray &in_blocks,
                   const VSPtrRangeArray &in_block_propa_ra,
                   const std::vector<ByteTaintPropagate *> &in_byte_propa);
  bool enc_block(uint32_t idx_block,
                 const RangeArray &in_blocks,
                 const VSPtrRangeArray &in_block_propa_ra,
                 const std::vector<ByteTaintPropagate *> &in_byte_propa);
  bool enc_last_block(uint32_t idx_block,
                      const RangeArray &in_blocks,
                      const VSPtrRangeArray &in_block_propa_ra,
                      const std::vector<ByteTaintPropagate *> &in_byte_propa);

  // Returns true if the block has:
  //  1:n, 1:n, 1:n, ect
  // pattern
  bool enc_block_pattern(uint32_t idx_block,
                         const RangeArray &in_blocks,
                         const VSPtrRangeArray &in_block_propa_ra);
  bool get_last_block_common(RangeArray &common,
                             const RangeArray &in_blocks,
                             const std::vector<ByteTaintPropagate *> &in_byte_propa);

  bool analyze_dec(const RangeArray &in_blocks,
                   const VSPtrRangeArray &in_block_propa_ra,
                   const std::vector<ByteTaintPropagate *> &in_byte_propa);

  bool dec_block(uint32_t idx_block,
                 const RangeArray &in_blocks,
                 const VSPtrRangeArray &in_block_propa_ra,
                 const std::vector<ByteTaintPropagate *> &in_byte_propa);
  // Returns true if last block has 1:1
  bool dec_last_block(uint32_t idx_block,
                      const RangeArray &in_blocks,
                      const VSPtrRangeArray &in_block_propa_ra,
                      const std::vector<ByteTaintPropagate *> &in_byte_propa);
  // Returns true if block has pattern:
  // 1:n
  bool dec_block_pattern(uint32_t idx_block,
                         const RangeArray &in_blocks,
                         const VSPtrRangeArray &in_block_propa_ra);
  bool dec_last_block_pattern(uint32_t idx_block,
                         const RangeArray &in_blocks,
                         const VSPtrRangeArray &in_block_propa_ra);
  // Returns true if has 1:1 to next block propagated range
  bool dec_byte(uint32_t idx_byte,
                uint32_t idx_block,
                const RangeArray &in_blocks,
                const VSPtrRangeArray &in_block_propa_ra,
                const std::vector<ByteTaintPropagate *> &in_byte_propa);

};

#endif //XT_CBCDETECTOR_H
