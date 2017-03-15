#include "xt_modedetect.h"

#include <iostream>
using namespace std;

int ModeDetect::TYPE_UNDEF = 0;
int ModeDetect::TYPE_ENC   = 1;
int ModeDetect::TYPE_DEC   = 2;

ModeDetect::ModeDetect() : input(0,0), output(0,0)
{
    DetectFactory::get_instance().register_detector(this);
    type_enc_dec = TYPE_UNDEF;
}

ModeDetect::~ModeDetect() {}

CBCDetect CBCDetect::cbc_;

bool CBCDetect::analyze_mode(vector<ByteTaintPropagate *> &v_in_propagate,
                             Blocks &blocks)
{
    cout << "analyzing mode: cbc..." << endl;

    // how many bytes in 1st block
    unsigned block_sz = blocks[0]->get_len();

    // finds the largest continuous buffer
    int b_first = blocks[0]->get_begin();
    int b_last   = blocks[blocks.size() - 1]->get_end() - 1;
    for(int i = 1; i < blocks.size(); i++){
        if(blocks[i]->get_begin() != blocks[i-1]->get_end() ){
            b_last = blocks[i - 1]->get_end() - 1;
        }
    }

    // detects mode and in/out size:
    // Pattern of cbc encryption:
    //  1:n, 1:n, 1:n...
    // Pattern of cbc dec:
    //  1:n, 1:1

    // first, detects mode by comparing the first two blocks
    int b_second = b_first + block_sz;
    ByteTaintPropagate *first_propagate = v_in_propagate[b_first];
    ByteTaintPropagate *second_propagate = v_in_propagate[b_second];

    bool type_done = false;

    return false;
}

bool CBCDetect::analyze_mode_alter(vector<ByteTaintPropagate *> &v_in_propagate,
                                   Blocks &blocks,
                                   unsigned int out_begin_addr,
                                   unsigned int out_len)
{
    cout << "analyzing mode: cbc..." << endl;

    // Detects cbc encryption or decryption:
    // Pattern of cbc encryption:
    //  1:n, 1:n, 1:n...
    // Pattern of cbc dec:
    //  1:n, 1:1
    // Determines by comparing the first two input blocks

    unsigned block_sz = blocks[0]->get_len();

    int first_block_begin = blocks[0]->get_begin();
    int second_block_begin = first_block_begin + block_sz;

    ByteTaintPropagate *first_b_begin_propa = v_in_propagate[first_block_begin];
    ByteTaintPropagate *second_b_begin_propa = v_in_propagate[second_block_begin];

    RangeArray common_range_first_b(out_begin_addr, out_len);
    RangeArray common_range_second_b(out_begin_addr, out_len);

    common_range_first_b.get_common_range(*first_b_begin_propa->get_taint_propagate() );
    common_range_second_b.get_common_range(*second_b_begin_propa->get_taint_propagate() );

    common_range_first_b.disp_range_array();
    common_range_second_b.disp_range_array();

    // If dec, the 1st block propagate range with 2nd block propagate range
    // only has 1 byte in common
    common_range_first_b.get_common_range(common_range_second_b);
    common_range_first_b.disp_range_array();

    // Only has 1 common range?
    if(common_range_first_b.get_size() == 1){
        if(common_range_first_b[0]->get_len() == 1){
            return analyze_dec(v_in_propagate, blocks, out_begin_addr, out_len);
        }else{
            return analyze_enc(v_in_propagate, blocks, out_begin_addr, out_len);
        }
    }
}

// If cbc enc, should have pattern:
//  1 : n, 1 : n,...
// If cbc dec, should have pattern:
//  1 : n,
//  1 : 1
// By comparing the first two blocks, we can determine if it is either
// enc or dec, or neither
bool CBCDetect::analyze_mode_improve(vector<ByteTaintPropagate *> &v_in_propagate,
                            Blocks &blocks,
                            unsigned int out_begin_addr,
                            unsigned int out_len)
{
    bool is_enc = false;
    bool is_dec = false;

    is_enc = analyze_enc_block(v_in_propagate, blocks, false, 0, out_begin_addr, out_len);
    is_dec = analyze_dec_block(v_in_propagate, blocks, false, 0, out_begin_addr, out_len);

    if(is_enc){
        type_enc_dec = TYPE_ENC;
        analyze_enc(v_in_propagate, blocks, out_begin_addr, out_len);
    }else if(is_dec){
        type_enc_dec = TYPE_DEC;
        analyze_dec(v_in_propagate, blocks, out_begin_addr, out_len);
    }else{
        return false;
    }

    return true;
}

inline bool CBCDetect::is_in_order_impact(unsigned int addr_to_nex_b_byte,
                                   unsigned int addr_next_b_r_begin,
                                   unsigned int idx_byte)
{
    if( (addr_to_nex_b_byte - addr_next_b_r_begin) == idx_byte ){
        return true;
    }else{
        return false;
    }
}

bool CBCDetect::analyze_enc(std::vector<ByteTaintPropagate *> &v_in_propagate,
                     Blocks &blocks,
                     unsigned int out_addr_begin,
                     unsigned int out_len)
{
    cout << "analyzing cbc enc..." << endl;

    bool is_found = false;

    int idx_b = 0;
    for(; idx_b < blocks.size(); idx_b++){
        bool is_last_block = (idx_b == blocks.size() - 1) ? true : false;
        is_found = analyze_enc_block(v_in_propagate, blocks, is_last_block, idx_b,
                out_addr_begin, out_len);

        if(is_found){
            cout << "detects block in cbc mode encryption: block id: " << idx_b << endl;
        }
    }

    return is_found;
}

bool CBCDetect::analyze_enc_block(vector<ByteTaintPropagate *> &v_in_propagate,
                     Blocks &blocks,
                     bool is_last,
                     unsigned int idx_block,
                     unsigned int out_addr_begin,
                     unsigned int out_len)
{
    if(!is_last){
        bool is_all_bytes_found = false;

        unsigned int block_sz = blocks[idx_block]->get_len();
        unsigned int idx_byte_begin = idx_block * block_sz;
        for(; idx_byte_begin < block_sz; idx_byte_begin++){
            is_all_bytes_found = analyze_enc_byte(v_in_propagate, blocks, idx_block,
                    idx_byte_begin, out_addr_begin, out_len);

            if(!is_all_bytes_found){
                return is_all_bytes_found;
            }
        }

        return is_all_bytes_found;
    }else {
        return true;
    }
}

bool CBCDetect::analyze_enc_byte(vector<ByteTaintPropagate *> &v_in_propagate,
                     Blocks &blocks,
                     unsigned int idx_block,
                     unsigned int idx_byte,
                     unsigned int out_addr_begin,
                     unsigned int out_len)
{
    ByteTaintPropagate *in_byte_propa = v_in_propagate[idx_byte];
    RangeArray in_byte_r(out_addr_begin, out_len);
    in_byte_r.get_common_range(*in_byte_propa->get_taint_propagate() );
    in_byte_r.disp_range_array();

    if(in_byte_r.get_size() != 1){
        cout << "analyze_enc_byte: in byte range array is not 1" << endl;
        return false;
    }

    int block_sz = blocks[idx_block]->get_len();
    int idx_out_block = idx_block + 1;
    // goes througth all rest blocks
    for(; idx_out_block < blocks.size(); idx_out_block++){
        // If in byte range contains all ranges of next blocks
        // Pattern: 1:n
        int idx_out_b_first_byte = idx_out_block * block_sz;
        ByteTaintPropagate *firstbyte_out_b_propa = v_in_propagate[idx_out_b_first_byte];
        RangeArray out_block_r(out_addr_begin, out_len);
        out_block_r.get_common_range(*firstbyte_out_b_propa->get_taint_propagate() );
        out_block_r.disp_range_array();

        if(out_block_r.get_size() != 1){
            cout << "analyze_enc_byte: in byte range array is not 1" << endl;
            return false;
        }

        // remove the common range with idx_out_block range
        if(in_byte_r.has_range(*out_block_r[0]) ){
            in_byte_r.del_range(out_block_r[0]->get_begin(), out_block_r[0]->get_len() );
            in_byte_r.disp_range_array();
        }else{
            return false;
        }
    }

    // After removing all common ranges with rest blocks, should only left
    // with range the current block decrypted text
    // the decrypted text buffer size should be same with the ciphertext block size
    if(in_byte_r[0]->get_len() == block_sz){
        return true;
    }else {
        return false;
    }
}

bool CBCDetect::analyze_dec(vector<ByteTaintPropagate *> &v_in_propagate,
                            Blocks &blocks,
                            unsigned int out_addr_begin,
                            unsigned int out_len)
{
    bool is_found = false;

    int idx_block = 0;
    for(idx_block = 0; idx_block < blocks.size(); idx_block++){
        bool is_last_block = (idx_block == blocks.size() - 1) ? true : false;
        is_found = analyze_dec_block(v_in_propagate, blocks, is_last_block, idx_block,
                out_addr_begin, out_len);

        if(is_found){
            cout << "detects block in cbc mode decryption: block id: " << idx_block << endl;
        }
    }

    return is_found;
}

// Detects the current block has the pattern: 1 : 1
bool CBCDetect::analyze_dec_block(vector<ByteTaintPropagate *> &v_in_propagate,
                                  Blocks &blocks,
                                  bool is_last,
                                  unsigned int idx_block,
                                  unsigned int out_addr_begin,
                                  unsigned int out_len)
{
    if(!is_last){
        unsigned int block_sz = blocks[idx_block]->get_len();
        unsigned int firstbyte_next_b = (idx_block+1) * block_sz;
        ByteTaintPropagate *firstbyte_next_b_propa = v_in_propagate[firstbyte_next_b];

        // Get the common range between next block propagate range and
        // the output range.
        // Get the length of common range
        RangeArray next_b_dec_range(out_addr_begin, out_len);
        next_b_dec_range.get_common_range(*firstbyte_next_b_propa->get_taint_propagate() );
        next_b_dec_range.disp_range_array();
        // Assumes it's first range
        unsigned int len_next_b_range = next_b_dec_range[0]->get_len();

        // Uses length of decrypted text of next block, instead of length
        // of current block decrypted text, due to if next block is the last,
        // then its size might be smaller than the decrypted text of current block
        bool is_all_bytes_found = true;
        int idx_byte = 0;
        for(; idx_byte < len_next_b_range; idx_byte++){
            is_all_bytes_found = analyze_dec_byte(v_in_propagate, blocks, idx_byte,
                    idx_block, out_addr_begin, out_len);

            if(!is_all_bytes_found){
                return is_all_bytes_found;
            }
        }

        // It must be all bytes in the block have the 1:1 pattern
        return is_all_bytes_found;
    }else{
        // last block does not has the pattern
        return true;
    }
}

// Detect the pattern 1:1 of current byte of current block
bool CBCDetect::analyze_dec_byte(vector<ByteTaintPropagate *> &v_in_propagate,
                                 Blocks &blocks,
                                 unsigned int idx_byte,
                                 unsigned int idx_block,
                                 unsigned int out_addr_begin,
                                 unsigned int out_len)
{
    bool is_one_to_one = false;
    bool is_successive = false;

    is_one_to_one = has_one_to_one_pattern(v_in_propagate, blocks, idx_byte, idx_block,
            out_addr_begin, out_len);
    is_successive = is_range_successive(v_in_propagate, blocks, idx_block,
            out_addr_begin, out_len);
    if(is_one_to_one && is_successive ){
        return true;
    }else{
        return false;
    }
}

bool CBCDetect::has_one_to_one_pattern(vector<ByteTaintPropagate *> &v_in_propagate,
                                       Blocks &blocks,
                                       unsigned int idx_byte,
                                       unsigned int idx_block,
                                       unsigned int out_addr_begin,
                                       unsigned int out_len)
{
    unsigned int block_sz = blocks[idx_block]->get_len();

    int idx_byte_curr_b = idx_block * block_sz + idx_byte;
    int idx_byte_next_b = (idx_block + 1) * block_sz + idx_byte;

    ByteTaintPropagate *byte_curr_b_propa = v_in_propagate[idx_byte_curr_b];
    ByteTaintPropagate *byte_next_b_propa = v_in_propagate[idx_byte_next_b];

    RangeArray byte_curr_b_r(out_addr_begin, out_len);
    RangeArray byte_next_b_r(out_addr_begin, out_len);

    byte_curr_b_r.get_common_range(*byte_curr_b_propa->get_taint_propagate() );
    byte_curr_b_r.disp_range_array();

    byte_next_b_r.get_common_range(*byte_next_b_propa->get_taint_propagate() );
    byte_next_b_r.disp_range_array();

    // Expect two ranges in byte_curr_b_r:
    //  1) decrypted buffer range of current block
    //  2) extra 1 byte of decrypted buffer of next block
    byte_curr_b_r.get_common_range(byte_next_b_r);
    byte_curr_b_r.disp_range_array();
    if(byte_curr_b_r.get_size() == 1 && byte_curr_b_r[0]->get_len() == 1){
        unsigned int to_next_b_byte_addr = byte_curr_b_r[0]->get_begin();
        unsigned int next_b_r_begin_addr = byte_next_b_r[0]->get_begin();

        return is_in_order_impact(to_next_b_byte_addr, next_b_r_begin_addr, idx_byte);
    }else{
        return false;
    }
}

bool CBCDetect::is_range_successive(vector<ByteTaintPropagate *> &v_in_propagate,
                             Blocks &blocks,
                             unsigned int idx_block,
                             unsigned int out_addr_begin,
                             unsigned int out_len)
{
    unsigned int block_sz = blocks[idx_block]->get_len();

    int idx_first_byte_curr_b = idx_block * block_sz;
    int idx_second_byte_curr_b = idx_block * block_sz + 1;
    int idx_first_byte_next_b = (idx_block + 1) * block_sz;

    ByteTaintPropagate *firstbyte_curr_b_propa = v_in_propagate[idx_first_byte_curr_b];
    ByteTaintPropagate *secbyte_curr_b_propa = v_in_propagate[idx_second_byte_curr_b];
    ByteTaintPropagate *firstbyte_next_b_propa = v_in_propagate[idx_first_byte_next_b];

    RangeArray curr_b_r(out_addr_begin, out_len);
    RangeArray next_b_r(out_addr_begin, out_len);

    curr_b_r.get_common_range(*firstbyte_curr_b_propa->get_taint_propagate() );
    curr_b_r.get_common_range(*secbyte_curr_b_propa->get_taint_propagate() );
    curr_b_r.disp_range_array();

    next_b_r.get_common_range(*firstbyte_next_b_propa->get_taint_propagate() );
    next_b_r.disp_range_array();

    if(curr_b_r.get_size() == 1 && curr_b_r[0]->get_end() == next_b_r[0]->get_begin() ){
        return true;
    }else {
        return false;
    }

}

DetectFactory DetectFactory::detect_factory_;
std::vector<ModeDetect *> DetectFactory::detectors;
