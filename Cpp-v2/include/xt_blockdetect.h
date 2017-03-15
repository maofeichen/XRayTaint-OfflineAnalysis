// Referenced Cipher Xray's code: class: BlockDetector

#ifndef XT_BLOCKDETECT_H_
#define XT_BLOCKDETECT_H_

#include "xt_ByteTaintPropagate.h"
#include "xt_modedetect.h"

#include <vector>

class BlockDetect{
public:
    unsigned int MIN_ADDRESS = 0x300;
    unsigned int MAX_ADDRESS = 0xc0000000;
    unsigned int WINDOW_SIZE = 64; // 64 bytes

    BlockDetect(unsigned int out_begin_addr, unsigned int out_len);
    ~BlockDetect() {};

    // Not used!
    void detect_block_size(Blocks &blocks,
                           std::vector<ByteTaintPropagate *> &buf_taint_propagate,
                           unsigned int in_byte_sz,
                           unsigned int out_addr,
                           unsigned int out_byte_sz);
    void detect_block_size_alter(Blocks &blocks,
                                 std::vector<ByteTaintPropagate *> &buf_taint_propagate,
                                 unsigned int in_byte_sz,
                                 unsigned int out_addr,
                                 unsigned int out_byte_sz);
    // Detects block for small buffer size < 64 bytes
    void detect_block_sz_small_win(Blocks &blocks,
                                 std::vector<ByteTaintPropagate *> &buf_taint_propagate,
                                 unsigned int in_byte_sz);

    void detect_mode_type(std::vector<ByteTaintPropagate *> &v_in_propagate,
                          Blocks &blocks);

private:
    unsigned int MIN_BLOCK_SZ     = 8;

    unsigned int out_begin_addr_  = 0;
    unsigned int out_len_         = 0;
    // Removes ranges smaller than minimum range in the given range array
    void rm_minimum_range(RangeArray &ra, unsigned int minimum_range);
    bool save_block(unsigned accumu_b_sz, Blocks &blocks,
            unsigned int &b_begin_byte, int i_byte);
};


#endif /* XT_BLOCKDETECT_H_ */
