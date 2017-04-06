// Referenced Cipher Xray's code: class: BlockDetector

#ifndef XT_BLOCKDETECT_H_
#define XT_BLOCKDETECT_H_

#include "xt_ByteTaintPropagate.h"
#include "xt_blockmodedetector.h"
#include "xt_modedetect.h"

#include <vector>

class BlockDetect {
 public:
  BlockDetect(unsigned int out_begin_addr,
              unsigned int out_len);
  BlockDetect(uint32_t in_begin_addr,
              uint32_t in_len,
              uint32_t out_begin_addr,
              uint32_t out_len);
  ~BlockDetect() {};

  void detect_block_size(RangeArray &input_blocks,
                         VSPtrRangeArray &input_block_propa,
                         std::vector<ByteTaintPropagate *> &buf_taint_propagate);
  void detect_block_size_ori(Blocks &blocks,
                             std::vector<ByteTaintPropagate *> &buf_taint_propagate,
                             unsigned int in_byte_sz,
                             unsigned int out_addr,
                             unsigned int out_byte_sz);
  void detect_block_size_alter(Blocks &blocks,
                               std::vector<ByteTaintPropagate *> &buf_taint_propagate,
                               unsigned int in_byte_sz,
                               unsigned int out_addr,
                               unsigned int out_byte_sz);
  // Detects block for small buffer size < 64 bytes?
  void detect_block_sz_small_win(Blocks &blocks,
                                 std::vector<ByteTaintPropagate *> &buf_taint_propagate,
                                 unsigned int in_byte_sz,
                                 unsigned int out_addr,
                                 unsigned int out_byte_sz);

  bool detect_mode_type(const RangeArray input_blocks,
                        const VSPtrRangeArray input_block_propa,
                        const std::vector<ByteTaintPropagate *> &v_in_propagate);
  void detect_mode_type_ori(std::vector<ByteTaintPropagate *> &v_in_propagate,
                            Blocks &blocks);

 private:
  unsigned int MIN_ADDRESS = 0x300;
  unsigned int MAX_ADDRESS = 0xc0000000;
  unsigned int WINDOW_SIZE = 64; // 64 bytes
  unsigned int MIN_BLOCK_SZ = 8;

  uint32_t in_begin_addr_;
  uint32_t in_len_;
  unsigned int out_begin_addr_ = 0;
  unsigned int out_len_ = 0;

  // block is essentially a range, thus using RangeAraay could represent blocks
  RangeArray in_blocks_;    // blocks detects in input
  // the common propagate range array that each block propagate to
  V_Ptr_RangeArray propa_out_ra_;

  RangeArray &get_in_blocks() { return in_blocks_; }
  V_Ptr_RangeArray &get_out_propa_ra() { return  propa_out_ra_; }

  // Detects blocks via both by addresses and values. Same block should
  // 1) propagate to same address range, and
  // 2) val of those ranges should be same
  void detect_block_size_with_val(std::vector<ByteTaintPropagate *> &buf_taint_propagate);
  // Detects blocks same as detect_block_size_with_val(...)
  // The diff is, for potential last block, we assume it is the last
  // We let the analyze function to determine if it is truely the last block
  void detect_block_size_handling_last_block(RangeArray &input_blocks,
                                             VSPtrRangeArray &input_block_propa,
                                             std::vector<ByteTaintPropagate *> &buf_taint_propagate);
  // Returns the intersected propagated range (stores in common), given byte
  // a and byte b.
  bool init_block(RangeArray &common,
                  uint32_t idx_byte_a,
                  uint32_t idx_byte_b,
                  std::vector<ByteTaintPropagate *> &buf_taint_propagate);
  // Returns the intersected propagated range between the common and the
  // given byte
  bool extend_block(RangeArray &common,
                    uint32_t idx_byte,
                    std::vector<ByteTaintPropagate *> &buf_taint_propagate);
  // Determines if a block ends by comparing previous accumulate common range,
  // with current byte accumulate common range
  bool is_block_end(RangeArray &common,
                    RangeArray &prev_common,
                    uint32_t accumu_b_sz);
  bool save_block(unsigned accumu_b_sz,
                  Blocks &blocks,
                  unsigned int &b_begin_byte,
                  int i_byte);
  bool save_block_with_val(uint32_t b_begin_idx,
                           uint32_t accumu_b_sz,
                           RangeArray &ra_common);
  bool store_block(RangeArray &input_blocks,
                   VSPtrRangeArray &input_block_propa,
                   uint32_t b_begin_idx,
                   uint32_t accumu_b_sz,
                   RangeArray &ra_common);

  bool detect_mode_type_with_val(const RangeArray input_blocks,
                                 const VSPtrRangeArray input_block_propa,
                                 const std::vector<ByteTaintPropagate *> &v_in_propagate);

  // Removes ranges smaller than minimum range in the given range array
  void rm_minimum_range(RangeArray &ra,
                        unsigned int minimum_range);

};

#endif /* XT_BLOCKDETECT_H_ */
