#include "xt_modedetect.h"

#include <iostream>
using namespace std;

int ModeDetect::TYPE_UNDEF = 0;
int ModeDetect::TYPE_ENC   = 1;
int ModeDetect::TYPE_DEC   = 2;

ModeDetect::ModeDetect() : input(0, 0), output(0, 0) {
  DetectFactory::get_instance().register_detector(this);
  type_enc_dec = TYPE_UNDEF;
  DetectFactory::get_instance().count_num_detector();
}

ModeDetect::~ModeDetect() {}

bool ModeDetect::is_padding(RangeArraySPtr last_block) {
  RangeArray last_out_block;
  last_out_block.add_range(*last_block->at(res_block_idx::idx_out_block) );

  const multimap<uint32_t,uint32_t> &byte_val_map =
      last_out_block.at(0)->get_byte_val_map();

  multimap<uint32_t,uint32_t>::const_reverse_iterator rit =
      byte_val_map.rbegin();

  // last byte's val indicates number of paddings
  uint32_t num_padding = rit->second;
  for(uint32_t i = 0; i < num_padding; i++) {
    cout << "addr: " << hex << rit->first << endl;
    cout << "val: " << hex << rit->second << endl;
    if(num_padding != rit->second) {
      return false;
    }
    rit++;
  }

//  for(; rit != byte_val_map.rbegin()+1; ++rit) {
//    cout << "addr: " << hex << rit->first << endl;
//    cout << "val: " << hex << rit->second << endl;
//    if(num_padding != rit->second) {
//      return false;
//    }
//  }

  return true;
}

void ModeDetect::rm_minimum_range(RangeArray &ra, unsigned int minimum_range) {
  for (int i = 0; i < ra.get_size();) {
    if (ra[i]->get_len() < minimum_range) {
      ra.remove_range(i);
      continue;
    }
    i++;
  }
}

DetectFactory DetectFactory::detect_factory_;
std::vector<ModeDetect *> DetectFactory::detectors_;

void DetectFactory::begin() {
  cout << "number of detectors_: " << detectors_.size() << endl;
  it_detector = detectors_.begin();
}

void DetectFactory::count_num_detector() {
  cout << "number of detectors_: " << detectors_.size() << endl;
}

void DetectFactory::register_detector(ModeDetect *det) {
  detectors_.push_back(det);
  cout << "number of detectors_: " << detectors_.size() << endl;
}

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

inline unsigned int CBCDetect::get_next_b_begin_addr(RangeArray &ra,
                                                     unsigned int addr_byte_to_next_b)
{
    for(int i = 0; i < ra.get_size(); i++) {
        Range r = *ra[i];
        if(r.has_range(addr_byte_to_next_b, 1) ) {
            return r.get_begin();
        }
    }
    return 0;
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
        unsigned int idx_byte_end   = (idx_block + 1) * block_sz;
        for(; idx_byte_begin < idx_byte_end; idx_byte_begin++){
            is_all_bytes_found =
                    analyze_enc_byte(v_in_propagate, blocks, idx_block, idx_byte_begin,
                            out_addr_begin, out_len);

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
    RangeArray in_byte_ra(out_addr_begin, out_len);
    // RangeArray in_byte_r(MIN_ADDRESS, MAX_ADDRESS - MIN_ADDRESS + 1);

    in_byte_ra.get_common_range(*in_byte_propa->get_taint_propagate() );
    in_byte_ra.disp_range_array();

    int block_sz = blocks[idx_block]->get_len();
    int i_rest_bks = idx_block + 1;

    // goes througth all rest blocks
    for(; i_rest_bks < blocks.size(); i_rest_bks++){
        // If in byte range contains all ranges of next blocks
        // Pattern: 1:n
        int i_rest_b_firstbyte = i_rest_bks * block_sz;
        ByteTaintPropagate *firstbyte_out_b_propa = v_in_propagate[i_rest_b_firstbyte];

        RangeArray out_block_ra(out_addr_begin, out_len);
        // RangeArray out_block_r(MIN_ADDRESS, MAX_ADDRESS - MIN_ADDRESS + 1);
        out_block_ra.get_common_range(*firstbyte_out_b_propa->get_taint_propagate() );
        out_block_ra.disp_range_array();

        if(in_byte_ra.get_size() != 1) {
            cout << "analyze enc byte: in_byte_ra size is not 1" << endl;
            return false;
        }else {
            // del its own range
            in_byte_ra.del_range(in_byte_ra[0]->get_begin(), block_sz);
        }

        // if(!analyze_enc_ra(in_byte_ra, out_block_ra) ){
        if(!analyze_enc_ra_alter(in_byte_ra, out_block_ra) ){
            return false;
        }
    }

    return true;

    // After removing all common ranges with rest blocks, should only left
    // with range the current block decrypted text
    // the decrypted text buffer size should be same with the ciphertext block size
    
    // if(in_byte_ra[0]->get_len() == block_sz){
    //     return true;
    // }else {
    //     return false;
    // }
}

bool CBCDetect::analyze_enc_ra(RangeArray &in_ra, RangeArray &out_ra)
{
    int i = 0;
    if(in_ra.get_size() != 1){
        rm_ident_ranges(in_ra, out_ra);
    }

    in_ra.disp_range_array();
    out_ra.disp_range_array();

    // cbc enc pattern could not be identical
    rm_ident_ranges(in_ra, out_ra);

    // If in range arrays has only one range left (observation)
    if(in_ra.get_size() == 1) {
        bool has_common = false;
        for(i = 0; i < out_ra.get_size(); i++){
            // if the range of in_ra contains any ranges in
            // the out_ra
            if(in_ra.has_range(*out_ra[i] ) ){
                in_ra.del_range(out_ra[i]->get_begin(),
                                out_ra[i]->get_len() );
                has_common = true;
            }
        }

        if(has_common){
            return true;
        } else{
            return false;
        }
    }

    return false;
}

bool CBCDetect::analyze_enc_ra_alter(RangeArray &in_ra, RangeArray &out_ra)
{
    in_ra.disp_range_array();
    out_ra.disp_range_array();

    if(in_ra.get_size() != 1 && out_ra.get_size() != 1) {
        cout << "analyze enc ra alter: given in out size is not 1" << endl;
        return false;
    }else {
        if(in_ra.has_ident_range(out_ra[0]->get_begin(),
                                 out_ra[0]->get_len() ) ) {
            return true;
        }else {
            return false;
        }
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
        unsigned int len_next_b_range = 0;
        bool is_sec_last_b = (idx_block == blocks.size() - 2) ? true : false;

        if(is_sec_last_b) {
            unsigned int i_1stbyte_curr_bk  = idx_block * block_sz;
            unsigned int i_1stbyte_next_bk = (idx_block+1) * block_sz;

            // Uses length of decrypted text of next block, instead of length
            // of current block decrypted text, due to if next block is the last,
            // then its size might be smaller than the decrypted text of current block
            len_next_b_range = get_next_bk_range_len(v_in_propagate, i_1stbyte_curr_bk, i_1stbyte_next_bk,
                    out_addr_begin, out_len);
        }else {
            len_next_b_range = block_sz;
        }

        if(len_next_b_range != 0) {
            // If the range > block sz, uses block sz
            len_next_b_range = min(len_next_b_range, block_sz);

            bool is_all_bytes_fit = true;
            int idx_byte = 0;

            for(; idx_byte < len_next_b_range /* &&
                  is_all_bytes_fit */; idx_byte++){
                is_all_bytes_fit = analyze_dec_byte(v_in_propagate, blocks, idx_byte,
                        idx_block, out_addr_begin, out_len);
            }

            // It must be all bytes in the block have the 1:1 pattern
            return is_all_bytes_fit;
        }else {
            return false;
        }
    }else{
        // Debug
        // unsigned int block_sz = blocks[idx_block]->get_len();
        // for(int i = 0; i < block_sz; i++) {
        //     has_one_to_one_pattern(v_in_propagate, blocks, i, idx_block, out_addr_begin, out_len);
        // }

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
        cout << "analyze_dec_byte: given byte does not fit the pattern of cbc in dec" << endl;
        return false;
    }
}

unsigned int CBCDetect::get_next_bk_range_len(vector<ByteTaintPropagate *> &v_in_propagate,
                                       unsigned int i_1stbyte_curr_bk,
                                       unsigned int i_1stbyte_next_bk,
                                       unsigned int out_addr_begin,
                                       unsigned int out_len)
{
    ByteTaintPropagate *firstbyte_curr_bk_propa = v_in_propagate[i_1stbyte_curr_bk];
    ByteTaintPropagate *firstbyte_next_bk_propa = v_in_propagate[i_1stbyte_next_bk];

    if(firstbyte_curr_bk_propa->get_taint_propagate()->get_size() == 0 ||
       firstbyte_next_bk_propa->get_taint_propagate()->get_size() == 0) {
        return 0;
    }

    RangeArray curr_ra(out_addr_begin, out_len);
    RangeArray next_ra(out_addr_begin, out_len);
    // RangeArray curr_ra(MIN_ADDRESS, MAX_ADDRESS - MIN_ADDRESS + 1);
    // RangeArray next_ra(MIN_ADDRESS, MAX_ADDRESS - MIN_ADDRESS + 1);

    curr_ra.get_common_range(*firstbyte_curr_bk_propa->get_taint_propagate() );
    next_ra.get_common_range(*firstbyte_next_bk_propa->get_taint_propagate() );

    curr_ra.disp_range_array();
    next_ra.disp_range_array();

    rm_ident_ranges(curr_ra, next_ra);
    // rm_contain_ranges(curr_ra, next_ra);

    curr_ra.disp_range_array();
    next_ra.disp_range_array();

    // To find: one range in current block should be successive with one range
    // in next block
    for(int i = 0; i < curr_ra.get_size(); i++){
        for(int j = 0; j < next_ra.get_size(); j++) {
            if( (curr_ra[i]->get_end() - 1) == next_ra[j]->get_begin() ) {
                return next_ra[j]->get_len();
            }
        }
    }

    // Or it contains the next block range
    for(int i = 0; i < next_ra.get_size(); i++) {
        Range r = *next_ra[i];
        if(curr_ra.has_range(r.get_begin(), r.get_len() ) ) {
            return r.get_end();
        }
    }

    return 0;
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

    RangeArray byte_curr_b_ra(out_addr_begin, out_len);
    RangeArray byte_next_b_ra(out_addr_begin, out_len);
    // RangeArray byte_curr_b_ra(MIN_ADDRESS, MAX_ADDRESS - MIN_ADDRESS + 1);
    // RangeArray byte_next_b_ra(MIN_ADDRESS, MAX_ADDRESS - MIN_ADDRESS + 1);

    byte_curr_b_ra.get_common_range(*byte_curr_b_propa->get_taint_propagate() );
    byte_next_b_ra.get_common_range(*byte_next_b_propa->get_taint_propagate() );

    byte_curr_b_ra.disp_range_array();
    byte_next_b_ra.disp_range_array();

    // rm_minimum_range(byte_curr_b_ra, MIN_BUF_SZ);
    rm_minimum_range(byte_next_b_ra, MIN_BUF_SZ);

    rm_ident_ranges(byte_curr_b_ra, byte_next_b_ra);
    // rm_contain_ranges(byte_curr_b_ra, byte_next_b_ra);

    byte_curr_b_ra.disp_range_array();
    byte_next_b_ra.disp_range_array();

    if(byte_curr_b_ra.get_size() == 0 || byte_next_b_ra.get_size() == 0) {
        return false;
    }
    // Expect two ranges in byte_curr_b_r:
    //  1) decrypted buffer range of current block
    //  2) extra 1 byte of decrypted buffer of next block
    byte_curr_b_ra.get_common_range(byte_next_b_ra);
    byte_curr_b_ra.disp_range_array();

    // Observation: byte_curr_b_ra may not contain 1 range,
    // but should with 1 byte len
    int i = 0;
    for(; i < byte_curr_b_ra.get_size(); i++) {
        Range r = *byte_curr_b_ra[i];

        for(int j = 0; j < r.get_len(); j++){
            bool is_in_order = false;

            unsigned int addr_byte_to_next_b = r.get_begin() + j;
            unsigned int addr_byte_next_b_begin =
                    get_next_b_begin_addr(byte_next_b_ra, addr_byte_to_next_b);

            is_in_order = is_in_order_impact(addr_byte_to_next_b, addr_byte_next_b_begin, idx_byte);
            if(is_in_order) {
                return true;
            }
        }
    }

    cout << "The given byte does not has 1:1 pattern to its next block" << endl;
    return false;
}

bool CBCDetect::is_range_successive(vector<ByteTaintPropagate *> &v_in_propagate,
                             Blocks &blocks,
                             unsigned int idx_block,
                             unsigned int out_addr_begin,
                             unsigned int out_len)
{
    unsigned int block_sz = blocks[idx_block]->get_len();

    int idx_1stbyte_curr_bk = idx_block * block_sz;
    int idx_2ndbyte_curr_bk = idx_block * block_sz + 1;
    int idx_1stbyte_next_bk = (idx_block + 1) * block_sz;

    ByteTaintPropagate *byte1st_curr_bk_propa = v_in_propagate[idx_1stbyte_curr_bk];
    ByteTaintPropagate *byte2nd_curr_bk_propa = v_in_propagate[idx_2ndbyte_curr_bk];
    ByteTaintPropagate *byte1st_next_b_propa = v_in_propagate[idx_1stbyte_next_bk];

    RangeArray curr_bk_ra(out_addr_begin, out_len);
    RangeArray next_bk_ra(out_addr_begin, out_len);
    // RangeArray curr_bk_ra(MIN_ADDRESS, MAX_ADDRESS - MIN_ADDRESS + 1);
    // RangeArray next_bk_ra(MIN_ADDRESS, MAX_ADDRESS - MIN_ADDRESS + 1);

    curr_bk_ra.get_common_range(*byte1st_curr_bk_propa->get_taint_propagate() );
    curr_bk_ra.get_common_range(*byte2nd_curr_bk_propa->get_taint_propagate() );
    next_bk_ra.get_common_range(*byte1st_next_b_propa->get_taint_propagate() );

    rm_minimum_range(curr_bk_ra, MIN_BUF_SZ);
    rm_minimum_range(next_bk_ra, MIN_BUF_SZ);

    rm_ident_ranges(curr_bk_ra, next_bk_ra);
    // rm_contain_ranges(curr_bk_ra, next_bk_ra);

    curr_bk_ra.disp_range_array();
    next_bk_ra.disp_range_array();

    // If contains
    for(int i = 0; i < next_bk_ra.get_size(); i++) {
        if(curr_bk_ra.has_range(next_bk_ra[i]->get_begin(), 1) ){
            return true;
        }
    }

    // If successive
    for(int i = 0; i < curr_bk_ra.get_size(); i++){
        for(int j = 0; j < next_bk_ra.get_size(); j++) {
            if(curr_bk_ra[i]->get_end() == next_bk_ra[j]->get_begin() ) {
                return true;
            }
        }
    }

    cout << "is_range_successive: given block is not successive to next block" << endl;
    return false;
}

void CBCDetect::rm_contain_ranges(RangeArray &ra1, RangeArray &ra2)
{
    int ra1_sz = ra1.get_size();
    int ra2_sz = ra2.get_size();

    int idx_ra1 = 0;
    int idx_ra2 = 0;

    while (idx_ra1 < ra1_sz) {
        while (idx_ra2 < ra2_sz) {
            ra1[idx_ra1]->disp_range();
            ra2[idx_ra2]->disp_range();

            unsigned int r1_begin = ra1[idx_ra1]->get_begin();
            unsigned int r1_len   = ra1[idx_ra1]->get_len();

            unsigned int r2_begin = ra2[idx_ra2]->get_begin();
            unsigned int r2_len   = ra2[idx_ra2]->get_len();

            if(ra1[idx_ra1]->has_range(r2_begin, r2_len) ) {
                ra1.remove_range(idx_ra1);
                ra2.remove_range(idx_ra2);

                ra1_sz = ra1.get_size();
                ra2_sz = ra2.get_size();
            }else if(ra2[idx_ra2]->has_range(r1_begin, r2_len) ){
                ra1.remove_range(idx_ra1);
                ra2.remove_range(idx_ra2);

                ra1_sz = ra1.get_size();
                ra2_sz = ra2.get_size();
            } else{
                idx_ra2++;
            }

            ra1.disp_range_array();
            ra2.disp_range_array();
        }
        idx_ra1++;
    }
}

void CBCDetect::rm_ident_ranges(RangeArray &ra1, RangeArray &ra2) {
  int ra2_sz = ra2.get_size();
  int i = 0;

  while (i < ra2_sz) {
    unsigned int r2_begin = ra2[i]->get_begin();
    unsigned int r2_len = ra2[i]->get_len();

    if (ra1.has_ident_range(r2_begin, r2_len)) {
      ra1.del_range(r2_begin, r2_len);
      ra2.del_range(r2_begin, r2_len);

      ra2_sz = ra2.get_size();
    } else {
      i++;
    }
  }
}

ECBDetect ECBDetect::ecb_;

bool ECBDetect::analyze_mode(std::vector<ByteTaintPropagate *> &v_in_propagate,
                             Blocks &blocks) {

}

bool ECBDetect::analyze_ecb_mode(vector<ByteTaintPropagate *> &v_in_propa,
                                 RangeArray &in_blocks,
                                 V_Ptr_RangeArray &out_propa_ra) {
  cout << "num of blocks: " << in_blocks.get_size() << endl;
  cout << "num of corresponding propagated range arrays: "
       << out_propa_ra.size() << endl;

  if(in_blocks.get_size() != out_propa_ra.size() ) {
    cout << "error: num of blocks and their propagated common ranges are not "
        "matched..." << endl;
    return false;
  }

  // We don't konw if it's enc or dec until recognizing its padding, thus
  // detects pattern first.
  // The pattern of ecb in both enc and dec are:
  // 1 : n
  uint32_t i = 0;
  while (i < in_blocks.get_size() ) {
    // Uses rangearray to store the detected block results:
    // 1) the 1st range is the input block range
    // 2) the 2nd range is the corresponding output block of the input
    RangeArray *res_block = new RangeArray();

    bool is_det = false;
    bool is_last_block = (i == in_blocks.get_size() - 1) ? true : false;

    if (!is_last_block) {
      is_det = analyze_ecb_block(*in_blocks[i], out_propa_ra[i], res_block);
      if (is_det) {
        if (v_res_block_.empty()) {
          // always stores the 1st detected blcok
          v_res_block_.push_back(RangeArraySPtr(res_block));
        } else {
          if (is_continuous_block(res_block)) {
            v_res_block_.push_back(RangeArraySPtr(res_block));
          } else {
            cout << "current result block is not continuous" << endl;
          }
        }
      } else {
        cout << "given block does not fit the pattern of ecb" << endl;
      }
    } else {
      uint32_t common_block_sz = v_res_block_.back()->at(0)->get_len();
      is_det = analyze_ecb_last_block(*in_blocks[i], common_block_sz,
                                     out_propa_ra[i], res_block);
      if(is_det &&
          is_continuous_block(res_block) ) {
        v_res_block_.push_back(RangeArraySPtr(res_block) );
      } else {
        cout << "last block is not continuous" << endl;
      }
    }

    i++;
  }

  analyze_ecb_enc_dec();
}

void ECBDetect::analyze_ecb_enc_dec() {
  if(v_res_block_.empty() ) {
    cout << "err: analyzing ecb enc or dec: there is no result block." << endl;
    return;
  }

  RangeArraySPtr last_block = v_res_block_.back();
  last_block->at(res_block_idx::idx_in_block)->disp_range();
  last_block->at(res_block_idx::idx_out_block)->disp_range();
  last_block->at(res_block_idx::idx_out_block)->disp_byte_val_map();

  if(is_padding(last_block) ){
    cout << "analyzing ecb: detects padding, it is a decryption operation"
         << endl;
  } else {
    cout << "analyzing ecb: detects no padding, it is a encryption operation"
         << endl;
  }
}

bool ECBDetect::analyze_ecb_block(Range &block,
                                  RangeArraySPtr block_propa_ra,
                                  RangeArray *res_block) {
  if(block.get_len() == 0) {
    cout << "analyze ecb block: given block is empty..." << endl;
    return false;
  }

  if(block_propa_ra->get_size() == 0) {
    cout << "analyze ecb block: given block propagated ranges are empty..."
         << endl;
    return false;
  }

  block.disp_range();
  block_propa_ra->at(0)->disp_range();
  block_propa_ra->at(0)->disp_byte_val_map();

  // We only consider the first range of the given propagated range arrays,
  // due to:
  // 1) ranges in range array are in increased order
  // 2) ecb mode is ...
  uint32_t block_sz             = block.get_len();
  uint32_t block_propa_range_sz = block_propa_ra->at(0)->get_len();

  if(block_propa_range_sz == block_sz) {
    res_block->add_range(block);
    res_block->add_range(*block_propa_ra->at(0) );

    res_block->at(0)->disp_range();
    res_block->at(1)->disp_range();
    res_block->at(1)->disp_byte_val_map();

    return true;
  } else if(block_propa_range_sz > block_sz) {
    // the propagated range of the block might be larger than the block size,
    // overtainted.
    // We only used the block sz
    res_block->add_range(block);

    // saves the block sz width propagate range
    multimap<uint32_t,uint32_t> byte_val_map;

    uint32_t addr = block_propa_ra->at(0)->get_begin();
    cout << "addr: " << hex << addr << endl;
    uint32_t end_addr = addr + block_sz;
    for(; addr < end_addr; addr++ ) {
      pair<multimap<uint32_t,uint32_t>::const_iterator,
           multimap<uint32_t,uint32_t>::const_iterator> ret;
      ret = block_propa_ra->at(0)->get_byte_val_map().equal_range(addr);

      for(multimap<uint32_t,uint32_t>::const_iterator it = ret.first;
          it != ret.second; ++it) {
        byte_val_map.insert(*it);
      }
    }

    res_block->add_range(block_propa_ra->at(0)->get_begin(),
                         block_sz, byte_val_map);

    res_block->at(0)->disp_range();
    res_block->at(1)->disp_range();
    res_block->at(1)->disp_byte_val_map();

  } else {
    cout << "analyze ecb block: the block propagated range is smaller than "
        "block size..." << endl;
    return false;
  }

}

bool ECBDetect::analyze_ecb_last_block(Range &block,
                                       uint32_t block_sz,
                                       RangeArraySPtr block_propa_ra,
                                       RangeArray *res_block) {
  if(block.get_len() == 0) {
    cout << "analyze ecb block: given block is empty..." << endl;
    return false;
  }

  if(block_propa_ra->get_size() == 0) {
    cout << "analyze ecb block: given block propagated ranges are empty..."
         << endl;
    return false;
  }

  block.disp_range();
  block_propa_ra->at(0)->disp_range();
  block_propa_ra->at(0)->disp_byte_val_map();

  // We only consider the first range of the given propagated range arrays,
  // due to:
  // 1) ranges in range array are in increased order
  // 2) ecb mode is ...
  uint32_t block_propa_range_sz = block_propa_ra->at(0)->get_len();

  if(block_propa_range_sz == block_sz) {
    res_block->add_range(block);
    res_block->add_range(*block_propa_ra->at(0) );

    res_block->at(0)->disp_range();
    res_block->at(1)->disp_range();
    res_block->at(1)->disp_byte_val_map();

    return true;
  } else if(block_propa_range_sz > block_sz) {
    // the propagated range of the block might be larger than the block size,
    // overtainted.
    // We only used the block sz
    res_block->add_range(block);

    // saves the block sz width propagate range
    multimap<uint32_t,uint32_t> byte_val_map;

    uint32_t addr = block_propa_ra->at(0)->get_begin();
    cout << "addr: " << hex << addr << endl;
    uint32_t end_addr = addr + block_sz;
    for(; addr < end_addr; addr++ ) {
      pair<multimap<uint32_t,uint32_t>::const_iterator,
           multimap<uint32_t,uint32_t>::const_iterator> ret;
      ret = block_propa_ra->at(0)->get_byte_val_map().equal_range(addr);

      for(multimap<uint32_t,uint32_t>::const_iterator it = ret.first;
          it != ret.second; ++it) {
        byte_val_map.insert(*it);
      }
    }

    res_block->add_range(block_propa_ra->at(0)->get_begin(),
                         block_sz, byte_val_map);

    res_block->at(0)->disp_range();
    res_block->at(1)->disp_range();
    res_block->at(1)->disp_byte_val_map();
  } else {
    cout << "analyze ecb block: the block propagated range is smaller than "
        "block size..." << endl;
    return false;
  }
}

bool ECBDetect::is_continuous_block(RangeArray *curr_res_block) {
  RangeArraySPtr prev_res_block = v_res_block_.back();

  bool is_block_continue        = false;
  bool is_propa_range_continue  = false;

  prev_res_block->at(0)->disp_range();
  curr_res_block->at(0)->disp_range();

  prev_res_block->at(1)->disp_range();
  prev_res_block->at(1)->disp_byte_val_map();
  curr_res_block->at(1)->disp_range();
  curr_res_block->at(1)->disp_byte_val_map();

  is_block_continue =
      prev_res_block->at(0)->is_continuous_range(*curr_res_block->at(0) );
  is_propa_range_continue =
      prev_res_block->at(1)->is_continuous_range(*curr_res_block->at(1) );

  if(is_block_continue && is_propa_range_continue) {
    return true;
  } else {
    cout << "current result block is not continuous with its previous" << endl;
    return false;
  }
}
