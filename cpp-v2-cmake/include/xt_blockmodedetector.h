// Referenced Cipher Xray's class: ModeDetector
#ifndef XT_MODEDETECTOR_H
#define XT_MODEDETECTOR_H

#include "xt_ByteTaintPropagate.h"
#include "RangeArray.h"
#include <memory>
#include <vector>

typedef std::shared_ptr<RangeArray> RangeArraySPtr;
typedef std::vector<RangeArraySPtr> VSPtrRangeArray;

class BlockModeDetector{
 public:
  BlockModeDetector() {};

  uint32_t type;

  virtual bool analyze_mode(const RangeArray &in_blocks,
                            const VSPtrRangeArray &in_block_propa_ra,
                            const std::vector<ByteTaintPropagate *> &in_byte_propa) = 0;
 protected:
  static uint8_t TYPE_UNDEF;
  static uint8_t TYPE_ENC;
  static uint8_t TYPE_DEC;

  bool valid_input(const RangeArray &in_blocks,
                   const VSPtrRangeArray &in_block_propa_ra,
                   const std::vector<ByteTaintPropagate *> &in_byte_propa);
};

class CFBDetector : public BlockModeDetector{
 public:
  CFBDetector();

  bool analyze_mode(const RangeArray &in_blocks,
                    const VSPtrRangeArray &in_block_propa_ra,
                    const std::vector<ByteTaintPropagate *> &in_byte_propa);
 private:
  // cfb avalanche pattern: 1 : 1, 1 : n, 1 : n, etc
  bool analyze_enc(const RangeArray &in_blocks,
                   const VSPtrRangeArray &in_block_propa_ra,
                   const std::vector<ByteTaintPropagate *> &in_byte_propa);
  bool analyze_enc_block(uint32_t idx_block,
                         const RangeArray &in_blocks,
                   const VSPtrRangeArray &in_block_propa_ra,
                   const std::vector<ByteTaintPropagate *> &in_byte_propa);
  bool analyze_enc_reg_block(uint32_t idx_block,
                         const RangeArray &in_blocks,
                   const VSPtrRangeArray &in_block_propa_ra,
                   const std::vector<ByteTaintPropagate *> &in_byte_propa);
  bool analyze_enc_last_sec_block(uint32_t idx_block,
                         const RangeArray &in_blocks,
                   const VSPtrRangeArray &in_block_propa_ra,
                   const std::vector<ByteTaintPropagate *> &in_byte_propa);
  bool analyze_enc_last_block(uint32_t idx_block,
                         const RangeArray &in_blocks,
                          const VSPtrRangeArray &in_block_propa_ra,
                   const std::vector<ByteTaintPropagate *> &in_byte_propa);

  // Returns true if the current block has 1 : n, 1 : n, 1 : n, ect. pattern
  bool analyze_enc_block_pattern(uint32_t idx_block,
                         const RangeArray &in_blocks,
                         const VSPtrRangeArray &in_block_propa_ra);

  bool analyze_enc_reg_byte(uint32_t idx_block_begin,
                            uint32_t idx_byte,
                            uint32_t block_begin_propa_addr,
                            const std::vector<ByteTaintPropagate *> &in_byte_propa);
  // Returns true if last byte of block has the 1:1 pattern
  bool analyze_enc_last_byte(uint32_t idx_block_begin,
                             uint32_t idx_byte,
                             uint32_t block_begin_propa_addr,
                             const std::vector<ByteTaintPropagate *> &in_byte_propa);

  // Returns true if the given byte has 1:1 pattern
  bool analyze_enc_byte_one_to_one(uint32_t idx_block_begin,
                                   uint32_t idx_byte,
                                   uint32_t block_begin_propa_addr,
                                   Range &to_one);

  uint32_t exclude_range_begin(const uint32_t l_begin, const uint32_t r_begin);
  bool analyze_dec();
};
#endif //XT_MODEDETECTOR_H
