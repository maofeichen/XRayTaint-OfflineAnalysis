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

    BlockDetect() {};
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
    void detect_mode_type(std::vector<ByteTaintPropagate *> &v_in_propagate,
                          Blocks &blocks);

private:
    // Removes ranges smaller than minimum range in the given range array
    void rm_minimum_range(RangeArray &ra, unsigned int minimum_range);
};


#endif /* XT_BLOCKDETECT_H_ */
