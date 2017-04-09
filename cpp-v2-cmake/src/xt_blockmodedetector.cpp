#include "xt_blockmodedetector.h"
#include <iostream>
using namespace std;

 uint8_t BlockModeDetector::TYPE_UNDEF = 0;
 uint8_t BlockModeDetector::TYPE_ENC   = 1;
 uint8_t BlockModeDetector::TYPE_DEC   = 2;

bool BlockModeDetector::valid_input(const RangeArray &in_blocks,
                                    const VSPtrRangeArray &in_block_propa_ra,
                                    const vector<ByteTaintPropagate *> &in_byte_propa)
{
  if(in_blocks.get_size() == 0 ||
      in_block_propa_ra.empty() ||
      in_byte_propa.empty() ) {
    cout << "Block Mode Detector: invalid input." << endl;
    return false;
  } else {
    return true;
  }
}

CFBDetector::CFBDetector() {}
bool CFBDetector::analyze_mode(const RangeArray &in_blocks,
                               const VSPtrRangeArray &in_block_propa_ra,
                               const std::vector<ByteTaintPropagate *> &in_byte_propa)
{
  if(!valid_input(in_blocks, in_block_propa_ra, in_byte_propa) ) {
    return false;
  }

//  for(uint32_t i = 0; i < in_block_propa_ra.size(); i++) {
//    in_block_propa_ra[i]->disp_range_array();
//  }

//  in_blocks.disp_range_array();
//  for(uint32_t i = 0; i < in_blocks.get_size(); i++) {
//    in_blocks[i]->disp_range();
//    cout << "block: " << i << " len: " << in_blocks[i]->get_len() << endl;
//  }

  // enc pattern:
  //    1:1,1:n,1:n,etc.
  // dec pattern:
  //    1:1,1:n
  // Thus,
  //  1) enc can propagate "more" ranges than dec
  //  2) if there is only two blocks, we can't distinguish
  bool is_enc = false;
  bool is_dec = false;

  if(in_blocks.get_size() <= 2) {
    cout << "cfb detector: given less or equal 2 blocks, there is no "
        "distinguishes between enc and dec" << endl;
    type = TYPE_UNDEF;
  } else {

    is_enc = analyze_enc_block(0, in_blocks, in_block_propa_ra, in_byte_propa);
//    for (uint32_t i = 0; i < in_blocks.get_size(); i++) {
//      in_blocks[i]->disp_range();
//      cout << "block: " << i << " len: " << in_blocks[i]->get_len() << endl;
//    }
    is_dec = analyze_dec_block(0, in_blocks, in_block_propa_ra, in_byte_propa);
    if(is_enc) {
      is_enc = analyze_enc(in_blocks, in_block_propa_ra, in_byte_propa);
      if(is_enc) {
        type = TYPE_ENC;
        return is_enc;
      }
    } else if(is_dec) {
      is_dec = analyze_dec(in_blocks, in_block_propa_ra, in_byte_propa);
      if(is_dec) {
        type = TYPE_DEC;
        return is_dec;
      }
    }
    return false;
  }
//  analyze_enc(in_blocks, in_block_propa_ra, in_byte_propa);
//  analyze_dec(in_blocks, in_block_propa_ra, in_byte_propa);

  in_blocks.disp_range_array();

  for (uint32_t i = 0; i < in_block_propa_ra.size(); i++) {
    in_block_propa_ra[i]->disp_range_array();
  }

}

bool CFBDetector::analyze_enc(const RangeArray &in_blocks,
                              const VSPtrRangeArray &in_block_propa_ra,
                              const std::vector<ByteTaintPropagate *> &in_byte_propa)
{
  for (uint32_t i = 0; i < in_blocks.get_size(); i++) {
    in_blocks[i]->disp_range();
    cout << "block: " << i << " len: " << in_blocks[i]->get_len() << endl;
  }

  uint32_t num_block = 0;
  for(uint32_t i = 0; i < in_blocks.get_size(); i++) {
    bool is_det;
    is_det = analyze_enc_block(i, in_blocks, in_block_propa_ra, in_byte_propa);

//    for (uint32_t i = 0; i < in_block_propa_ra.size(); i++) {
//      in_block_propa_ra[i]->disp_range_array();
//    }

    if(is_det) {
      cout << "detect block: " << i << endl;
      uint32_t block_sz = in_blocks[i]->get_len();

      uint32_t input_end = input_.get_end();
      input_end += block_sz;
      input_.set_end(input_end);

      uint32_t output_end = output_.get_end();
      output_end += block_sz;
      output_.set_end(output_end);

      num_block++;
    }
  }

  bool is_dtct = false;
  if (input_.get_len() > 0) {
    uint32_t block_sz = in_blocks[0]->get_len();
    if (in_block_propa_ra[0]->at(0)->get_len() == block_sz * (num_block - 1)) {
      // the first block propagated range must be len of total detected block sz
      // except the first one
      is_dtct = true;
    } else {
      is_dtct = false;
    }
  }

  input_.disp_range();
  output_.disp_range();

  return is_dtct;
}

bool CFBDetector::analyze_dec(const RangeArray &in_blocks,
                              const VSPtrRangeArray &in_block_propa_ra,
                              const std::vector<ByteTaintPropagate *> &in_byte_propa)
{
  for (uint32_t i = 0; i < in_block_propa_ra.size(); i++) {
    in_block_propa_ra[i]->disp_range_array();
  }

  for(uint32_t i = 0; i < in_blocks.get_size(); i++) {
    if(i == 4) {
      cout << "5th block" << endl;
    }

    bool is_det;
    is_det = analyze_dec_block(i, in_blocks, in_block_propa_ra, in_byte_propa);

    if(is_det) {
      cout << "detect block: " << i << endl;
      uint32_t block_sz = in_blocks[i]->get_len();

      uint32_t end      = output_.get_end();
      end += block_sz;
      output_.set_end(end);

      uint32_t input_end = input_.get_end();
      input_end += block_sz;
      input_.set_end(input_end);
    }
  }
  input_.disp_range();
  output_.disp_range();
}


bool CFBDetector::analyze_enc_block(uint32_t idx_block,
                                    const RangeArray &in_blocks,
                                    const VSPtrRangeArray &in_block_propa_ra,
                                    const vector<ByteTaintPropagate *> &in_byte_propa)
{
  for(uint32_t i = 0; i < in_blocks.get_size(); i++) {
    cout << "block: " << i << " len: " << in_blocks[i]->get_len() << endl;
  }

  // output begin addr if init block
  if(idx_block == 0) {
//    set_output_begin(0, 0, in_blocks, in_byte_propa);

    uint32_t out_begin_addr =
        in_byte_propa[0]->get_taint_propagate()->at(0)->get_begin();
    output_.set_begin(out_begin_addr);
    output_.set_end(out_begin_addr);

    input_.set_begin(0);
    input_.set_end(0);
  }

  for(uint32_t i = 0; i < in_blocks.get_size(); i++) {
    cout << "block: " << i << " len: " << in_blocks[i]->get_len() << endl;
  }

  uint32_t num_block = in_blocks.get_size();
  bool is_last       = (idx_block == num_block - 1) ? true : false;
  bool is_last_sec   = (idx_block == num_block - 2) ? true : false;
  bool is_det = false;

  if(is_last) {
    is_det = enc_last_block(idx_block, in_blocks, in_block_propa_ra,
                            in_byte_propa);
  } else if(is_last_sec) {
    is_det = enc_last_sec_block(idx_block, in_blocks,
                                in_block_propa_ra, in_byte_propa);
  } else {
    is_det = enc_reg_block(idx_block, in_blocks, in_block_propa_ra,
                           in_byte_propa);
  }

  if(!is_det) {
    cout << "cfb enc detector: given block does not has the pattern" << endl;
  }
  return is_det;
}

bool CFBDetector::analyze_dec_block(uint32_t idx_block,
                                    const RangeArray &in_blocks,
                                    const VSPtrRangeArray &in_block_propa_ra,
                                    const vector<ByteTaintPropagate *> &in_byte_propa)
{
  if(idx_block == 0) {
//    set_output_begin(0, 0, in_blocks, in_byte_propa);

    // if is first block, set the potentional output begin address
    in_byte_propa[0]->get_taint_propagate()->disp_range_array();

    // ToDo: currently works fine, but should be first propagated range of
    // current output, instead of whole address space.
    // Also, 0 is not the only case that begining of a cipher
    uint32_t out_begin_addr =
        in_byte_propa[0]->get_taint_propagate()->at(0)->get_begin();
    output_.set_begin(out_begin_addr);
    output_.set_end(out_begin_addr);

    input_.set_begin(0);
    input_.set_end(0);
  }

  uint32_t num_block = in_blocks.get_size();
  bool is_last = (idx_block == num_block - 1) ? true : false;
  bool is_last_sec = (idx_block == num_block - 2) ? true : false;
  bool is_det = false;

  if(is_last) {
    is_det = dec_last_block(idx_block, in_blocks, in_block_propa_ra,
                            in_byte_propa);
  } else if(is_last_sec) {
//    is_det = dec_reg_block(idx_block, in_blocks, in_block_propa_ra,
//                           in_byte_propa);
    is_det = dec_last_sec_block(idx_block, in_blocks, in_block_propa_ra,
                                in_byte_propa);
  } else {
    is_det = dec_reg_block(idx_block, in_blocks, in_block_propa_ra,
                           in_byte_propa);
  }

  return is_det;
}

bool CFBDetector::enc_reg_block(uint32_t idx_block,
                                const RangeArray &in_blocks,
                                const VSPtrRangeArray &in_block_propa_ra,
                                const vector<ByteTaintPropagate *> &in_byte_propa)
{
  for(uint32_t i = 0; i < in_blocks.get_size(); i++) {
    cout << "block: " << i << " len: " << in_blocks[i]->get_len() << endl;
  }

  bool has_block_pattern = false;
  has_block_pattern = enc_block_pattern(idx_block, in_blocks,
                                        in_block_propa_ra);

  if(has_block_pattern) {
    uint32_t block_sz = in_blocks.at(idx_block)->get_len();

    uint32_t idx_b_begin = idx_block * block_sz;
    uint32_t i_b_end   = idx_b_begin + block_sz;

    uint32_t b_begin_propa_addr =
        in_byte_propa[idx_b_begin]->get_taint_propagate()->at(0)->get_begin();

    uint32_t i = idx_b_begin;
    for(; i < i_b_end; i++) {
      in_byte_propa[i]->get_taint_propagate()->disp_range_array();

      bool is_last = (i == i_b_end-1) ? true : false;
      bool is_det = false;

      if(is_last) {
        is_det = analyze_enc_last_byte(idx_b_begin, i, b_begin_propa_addr,
                                       in_byte_propa);
      } else{
        is_det = analyze_enc_byte(idx_b_begin, i, b_begin_propa_addr,
                                  in_byte_propa);
      }

      if(!is_det) {
        return false;
      }
    }

    return true;
  } else {
    cout << "cfb enc reg block: given block does not fit the pattern" << endl;
    return false;
  }
}

bool CFBDetector::enc_last_sec_block(uint32_t idx_block,
                                     const RangeArray &in_blocks,
                                     const VSPtrRangeArray &in_block_propa_ra,
                                     const vector<ByteTaintPropagate *> &in_byte_propa)
{
  // Last sec block is the last block to have a common propagated range. Its
  // correctness is garanteen by its previous block.
  // We only need verify the 1:1 pattern
  uint32_t block_sz    = in_blocks.at(idx_block)->get_len();
  uint32_t idx_b_begin = idx_block * block_sz;
  uint32_t idx_b_end   = idx_b_begin + block_sz;

  uint32_t b_begin_propa_addr =
      in_byte_propa[idx_b_begin]->get_taint_propagate()->at(0)->get_begin();


  uint32_t i = idx_b_begin;
  for(; i < idx_b_end; i++) {
    in_byte_propa[i]->get_taint_propagate()->disp_range_array();

    bool is_last = (i == idx_b_end - 1) ? true : false;
    bool is_det = false;

    if(is_last) {
      is_det = analyze_enc_last_byte(idx_b_begin, i, b_begin_propa_addr,
                                          in_byte_propa);
    } else {
      // just reuse
      is_det = analyze_enc_byte(idx_b_begin, i, b_begin_propa_addr,
                                     in_byte_propa);
    }

    if(!is_det) {
      cout << "cfb enc last sec block: does not fit pattern" << endl;
      return false;
    }
  }

  return true;
}

bool CFBDetector::enc_last_block(uint32_t idx_block,
                                 const RangeArray &in_blocks,
                                 const VSPtrRangeArray &in_block_propa_ra,
                                 const std::vector<ByteTaintPropagate *> &in_byte_propa)
{
  // Last block does not has a common range, it only has 1:1 pattern
  uint32_t prev_block_sz  = in_blocks.at(idx_block-1)->get_len();
  uint32_t block_sz       = in_blocks.at(idx_block)->get_len();

  uint32_t idx_b_begin    = idx_block * prev_block_sz;
  uint32_t idx_b_end      = idx_b_begin + block_sz;

  uint32_t b_begin_propa_addr =
      in_byte_propa[idx_b_begin]->get_taint_propagate()->at(0)->get_begin();

  uint32_t i = idx_b_begin;
  for(; i < idx_b_end; i++) {
    cout << "byte index: " << i << endl;
    in_byte_propa[i]->get_taint_propagate()->disp_range_array();

    bool is_byte_det = false;
    is_byte_det = analyze_enc_byte(idx_b_begin, i, b_begin_propa_addr,
                                   in_byte_propa);
//    is_byte_det = analyze_enc_last_byte(idx_b_begin, i, b_begin_propa_addr,
//                                       in_byte_propa);

    if (!is_byte_det) {
      cout << "cfb enc last block: does not fit pattern" << endl;
      return false;
    }
  }

  return true;
}

bool CFBDetector::dec_reg_block(uint32_t idx_block,
                                const RangeArray &in_blocks,
                                const VSPtrRangeArray &in_block_propa_ra,
                                const vector<ByteTaintPropagate *> &in_byte_propa)
{
  bool has_block_pattern = false;
  has_block_pattern = dec_block_pattern(idx_block, in_blocks,
                                        in_block_propa_ra);

  if(has_block_pattern) {
    uint32_t block_sz = in_blocks.at(idx_block)->get_len();

    uint32_t idx_b_begin = idx_block * block_sz;
    uint32_t i_b_end   = idx_b_begin + block_sz;

    uint32_t b_begin_propa_addr =
        in_byte_propa[idx_b_begin]->get_taint_propagate()->at(0)->get_begin();

    uint32_t i = idx_b_begin;
    for(; i < i_b_end; i++) {
      if(i == 46) {
        cout << "i is 46" << endl;
      }

      in_byte_propa[i]->get_taint_propagate()->disp_range_array();

      bool is_last = (i == i_b_end-1) ? true : false;
      bool is_byte_det = false;
      if(is_last) {
        is_byte_det = analyze_enc_last_byte(idx_b_begin, i, b_begin_propa_addr,
                                            in_byte_propa);
      } else{
//        is_byte_det = analyze_enc_byte(idx_b_begin, i, b_begin_propa_addr,
//                                       in_byte_propa);
        is_byte_det = analyze_enc_last_byte(idx_b_begin, i,
                                            b_begin_propa_addr, in_byte_propa);
      }

      if(!is_byte_det) {
        return false;
      }
    }

    return true;
  } else {
    cout << "cfb dec: the block does not fit pattern" << endl;
    return false;
  }
}

bool CFBDetector::dec_last_sec_block(uint32_t idx_block,
                                     const RangeArray &in_blocks,
                                     const VSPtrRangeArray &in_block_propa_ra,
                                     const std::vector<ByteTaintPropagate *> &in_byte_propa)
{
  // Last sec block has a common range that there is no compare
  uint32_t prev_block_sz    = in_blocks.at(idx_block-1)->get_len();
  uint32_t curr_block_sz    = in_blocks.at(idx_block)->get_len();
  uint32_t idx_b_begin = idx_block * prev_block_sz;
  uint32_t idx_b_end   = idx_b_begin + curr_block_sz;

  uint32_t b_begin_propa_addr =
      in_byte_propa[idx_b_begin]->get_taint_propagate()->at(0)->get_begin();

  uint32_t i = idx_b_begin;
  for(; i < idx_b_end; i++) {
    cout << "byte idx: " << i << endl;
    in_byte_propa[i]->get_taint_propagate()->disp_range_array();

    bool is_byte_det = false;
//    is_byte_det = analyze_enc_byte(idx_b_begin, i, b_begin_propa_addr,
//                                       in_byte_propa);
    is_byte_det = analyze_enc_last_byte(idx_b_begin, i, b_begin_propa_addr,
                                       in_byte_propa);

    if (!is_byte_det) {
      cout << "cfb dec last block: does not fit pattern" << endl;
      return false;
    }
  }

  return true;
}

bool CFBDetector::dec_last_block(uint32_t idx_block,
                                 const RangeArray &in_blocks,
                                 const VSPtrRangeArray &in_block_propa_ra,
                                 const vector<ByteTaintPropagate *> &in_byte_propa)
{
  // Last block does not has a common range, it only has 1:1 pattern
  uint32_t prev_block_sz    = in_blocks.at(idx_block-1)->get_len();
  uint32_t curr_block_sz    = in_blocks.at(idx_block)->get_len();
  uint32_t idx_b_begin = idx_block * prev_block_sz;
  uint32_t idx_b_end   = idx_b_begin + curr_block_sz;

  uint32_t b_begin_propa_addr =
      in_byte_propa[idx_b_begin]->get_taint_propagate()->at(0)->get_begin();

  uint32_t i = idx_b_begin;
  for(; i < idx_b_end; i++) {
    cout << "byte idx: " << i << endl;
    in_byte_propa[i]->get_taint_propagate()->disp_range_array();

    bool is_byte_det = false;
    is_byte_det = analyze_enc_byte(idx_b_begin, i, b_begin_propa_addr,
                                       in_byte_propa);
//    is_byte_det = analyze_enc_last_byte(idx_b_begin, i, b_begin_propa_addr,
//                                       in_byte_propa);

    if (!is_byte_det) {
      cout << "cfb dec last block: does not fit pattern" << endl;
      return false;
    }
  }

  return true;
}

bool CFBDetector::enc_block_pattern(uint32_t idx_block,
                                    const RangeArray &in_blocks,
                                    const VSPtrRangeArray &in_block_propa_ra)
{
  if(idx_block >= in_block_propa_ra.size() ||
      idx_block+1 >= in_block_propa_ra.size() ) {
    cout << "cfb enc block pattern: idx block is invalid" << endl;
    return false;
  }

  // If a block has 1:n,1:n,1:n etc. pattern, it indicates that, it (a) and its
  // next block (b), should:
  // 1) a's begin addr substract current output end addr should be block sz
  // 2) has same range end
  // 3) if a's range excludes b's range, should only left range with 1 block sz

  if(in_block_propa_ra[idx_block]->get_size() == 0 ||
      in_block_propa_ra[idx_block+1]->get_size() == 0) {
    cout << "cfb enc block pattern: propagated range arraies are empty"
         << endl;
    return false;
  }

  in_block_propa_ra[idx_block]->disp_range_array();
  in_block_propa_ra[idx_block+1]->disp_range_array();

  Range curr_propa_r(*in_block_propa_ra[idx_block]->at(0) );
  Range next_propa_r(*in_block_propa_ra[idx_block+1]->at(0) );

  curr_propa_r.disp_range();
  next_propa_r.disp_range();

  bool to_next_block = false;
  bool has_same_end  = false;
  bool has_exclu_pat = false;

  for(uint32_t i = 0; i < in_blocks.get_size(); i++) {
    cout << "block: " << i << " len:" << in_blocks[i]->get_len();
  }

  uint32_t block_sz = in_blocks.at(idx_block)->get_len();

  to_next_block = (curr_propa_r.get_begin() - output_.get_end() == block_sz);
  has_same_end = (curr_propa_r.get_end() == next_propa_r.get_end() );

  uint32_t curr_begin = curr_propa_r.get_begin();
  uint32_t next_begin = next_propa_r.get_begin();
  uint32_t diff       = exclude_range_begin(curr_begin, next_begin);
  if(diff == block_sz) {
    has_exclu_pat = true;
  } else {
    has_exclu_pat = false;
  }

  if(to_next_block &&
      has_same_end &&
      has_exclu_pat) {
    return true;
  } else {
    cout << "cfb enc detector: given block does not has block pattern" << endl;
    return false;
  }
}

bool CFBDetector::dec_block_pattern(uint32_t idx_block,
                                    const RangeArray &in_blocks,
                                    const VSPtrRangeArray &in_block_propa_ra)
{
  // If a block has 1 : n pattern, it indicates:
  // 1) to the current output begin address is block sz width, due to the
  // propagated range is to next output block
  // 2) its size should be larger than block sz
  // 3) to distinguish with cfb enc, it and its next block, should have
  // different propagated end

  if(idx_block+1 >= in_block_propa_ra.size() ) {
    cout << "cfb dec block pattern: given idx + 1 is invalid" << endl;
    return false;
  }

  in_block_propa_ra[idx_block]->disp_range_array();

  Range curr_propa_r(*in_block_propa_ra[idx_block]->at(0) );
  Range next_propa_r(*in_block_propa_ra[idx_block+1]->at(0) );

  if(curr_propa_r.get_len() == 0 || next_propa_r.get_len() == 0) {
    cout << "cfb dec block pattern: given ranges are empty" << endl;
    return false;
  }

  curr_propa_r.disp_range();
  next_propa_r.disp_range();

  uint32_t block_sz = in_blocks.at(idx_block)->get_len();

  uint32_t output_end = output_.get_begin();
  uint32_t output_len = output_.get_len();
  output_end += output_len;

  bool is_offset_curr_b = (curr_propa_r.get_begin() - output_end == block_sz);
  bool has_propa_whole_block = curr_propa_r.get_len() >= block_sz;
  // bool has_diff_end     = next_propa_r.get_end() != curr_propa_r.get_end();

  if(is_offset_curr_b &&
      has_propa_whole_block /* &&
      has_diff_end */) {
    return true;
  } else {
    cout << "cfb dec does not has block pattern" << endl;
    return false;
  }

//  if(curr_propa_r.get_begin() - output_end == block_sz &&
//      curr_propa_r.get_end() >= block_sz) {
//    return true;
//  } else {
//    cout << "cfb dec does not has block pattern" << endl;
//    return false;
//  }
}

bool CFBDetector::analyze_enc_byte(uint32_t idx_block_begin,
                                   uint32_t idx_byte,
                                   uint32_t block_begin_propa_addr,
                                   const vector<ByteTaintPropagate *> &in_byte_propa)
{
  bool has_one_to_one = false;
  Range to_one(*in_byte_propa[idx_byte]->get_taint_propagate()->at(0) );

  has_one_to_one = enc_byte_one_to_one(idx_block_begin, idx_byte,
                                       block_begin_propa_addr,
                                       to_one);

  if(has_one_to_one) {
    return true;
  } else {
    cout << "cfb enc reg byte: does not has byte pattern" << endl;
    return false;
  }
}

// We don't limit the range must be 1byte, because it is connected to the
// next block propagated range
bool CFBDetector::analyze_enc_last_byte(uint32_t idx_block_begin,
                                        uint32_t idx_byte,
                                        uint32_t block_begin_propa_addr,
                                        const std::vector<ByteTaintPropagate *> &in_byte_propa)
{
  bool has_pattern = false;
  Range to_one(*in_byte_propa[idx_byte]->get_taint_propagate()->at(0));

  if(to_one.get_len() <= 0){
    cout << "err: cfb enc last byte: given range is empty" << endl;
    return false;
  } else{
    uint32_t diff = idx_byte - idx_block_begin;
    uint32_t begin_byte_propa_addr = to_one.get_begin();

    if( (begin_byte_propa_addr - block_begin_propa_addr) == diff) {
      return true;
    } else {
      cout << "cfb enc last byte: does not has 1:1 pattern" << endl;
      return false;
    }
  }
}

bool CFBDetector::enc_byte_one_to_one(uint32_t idx_block_begin,
                                      uint32_t idx_byte,
                                      uint32_t block_begin_propa_addr,
                                      Range &to_one)
{
  if(to_one.get_len() != 1) {
    cout << "cfb enc byte 1:1 pattern: err given range is not 1 byte" << endl;
    return false;
  } else {
    uint32_t byte_propa_begin_addr = to_one.get_begin();
    if( (idx_byte - idx_block_begin) ==
        (byte_propa_begin_addr - block_begin_propa_addr) ) {
      return true;
    } else {
      cout << "cfb enc byte to byte impact pattern: fails" << endl;
      return false;
    }
  }
}

uint32_t CFBDetector::exclude_range_begin(const uint32_t l_begin,
                                          const uint32_t r_begin)
{
  uint32_t diff = 0;

  if(l_begin > r_begin) {
    return diff;
  } else {
    diff = r_begin - l_begin;
    return diff;
  }
}

inline void CFBDetector::set_output_begin(uint32_t idx_block,
                                          uint32_t idx_byte,
                                          const RangeArray in_blocks,
                                          const vector<ByteTaintPropagate *> &in_byte_propa)
{
  if(idx_block >= in_blocks.get_size() ) {
    cout << "cfb detector: set output begin: given block idx is invalid" << endl;
    return;
  }

  for(uint32_t i = 0; i < in_blocks.get_size(); i++) {
    cout << "block: " << i << " len: " << in_blocks[i]->get_len() << endl;
  }

  uint32_t block_sz       = in_blocks[idx_block]->get_len();
  uint32_t idx            = idx_block * block_sz + idx_byte;

  if(idx >= in_byte_propa.size() ) {
    cout << "cfb detector: set output begin: given byte idx is invalid" << endl;
    return;
  }

  in_byte_propa[idx]->get_taint_propagate()->disp_range_array();

  // ToDo: currently works fine, but should be
  // 1) first propagated range of current output, instead of whole address
  // space.
  // 2) Also, 0 is not the only case that begining of a cipher
  uint32_t out_begin_addr =
      in_byte_propa[idx]->get_taint_propagate()->at(0)->get_begin();
  output_.set_begin(out_begin_addr);
  output_.set_end(out_begin_addr);

  for(uint32_t i = 0; i < in_blocks.get_size(); i++) {
    cout << "block: " << i << " len: " << in_blocks[i]->get_len() << endl;
  }
}

