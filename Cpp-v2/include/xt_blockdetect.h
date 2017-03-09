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

    void detect_block_size(Blocks &blocks,
                           std::vector<ByteTaintPropagate *> &buf_taint_propagate,
                           unsigned int in_byte_sz,
                           unsigned int out_addr,
                           unsigned int out_byte_sz);
private:
};



#endif /* XT_BLOCKDETECT_H_ */
