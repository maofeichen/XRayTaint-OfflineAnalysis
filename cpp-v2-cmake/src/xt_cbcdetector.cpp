#include "xt_cbcdetector.h"
#include <vector>
#include <iostream>

using namespace std;

CBCDetector::CBCDetector(uint32_t output_begin, uint32_t output_sz)
{
  output_begin_ = output_begin;
  output_sz_    = output_sz;
}

bool CBCDetector::analyze_mode(const RangeArray &in_blocks,
                               const VSPtrRangeArray &in_block_propa_ra,
                               const vector<ByteTaintPropagate *> &in_byte_propa)
{
  if(!valid_input(in_blocks, in_block_propa_ra, in_byte_propa) ) {
    return false;
  }

  cout << "num of block: " << in_blocks.get_size() << endl;
  cout << "num of block propagation: " << in_block_propa_ra.size() << endl;

  cout << "blocks detected: " << endl;
  in_blocks.disp_range_array();

  cout << "blocks common propagated ranges: " << endl;
  for (int i = 0; i < in_block_propa_ra.size(); ++i) {
    cout << "block: " << i << " propagates to: " << endl;
    in_block_propa_ra[i]->disp_range_array();
  }

  bool is_enc = false;
  bool is_dec = false;

  is_enc = analyze_enc(in_blocks, in_block_propa_ra, in_byte_propa);
  if(is_enc) {
    type = TYPE_ENC;
    return is_enc;
  }

  is_dec = analyze_dec(in_blocks, in_block_propa_ra, in_byte_propa);
  if(is_dec) {
    type = TYPE_DEC;
    return is_dec;
  }

  return false;

  is_enc = enc_block(0, in_blocks, in_block_propa_ra, in_byte_propa) &&
           enc_block(1, in_blocks, in_block_propa_ra, in_byte_propa);
  is_dec = dec_block(0, in_blocks, in_block_propa_ra, in_byte_propa) &&
           dec_block(1, in_blocks, in_block_propa_ra, in_byte_propa);

  bool is_det;
  if(is_enc) {
    is_det = analyze_enc(in_blocks, in_block_propa_ra, in_byte_propa);
    if(is_det) {
      type = TYPE_ENC;
    }
  } else if(is_dec) {
    is_det = analyze_dec(in_blocks, in_block_propa_ra, in_byte_propa);
    if(is_det) {
      type = TYPE_DEC;
    }
  }
}

bool CBCDetector::analyze_enc(const RangeArray &in_blocks,
                              const VSPtrRangeArray &in_block_propa_ra,
                              const vector<ByteTaintPropagate *> &in_byte_propa)
{
  VSPtrRangeArray in_block_prpgt;
  for(auto it = in_block_propa_ra.begin(); it != in_block_propa_ra.end(); ++it) {
    in_block_prpgt.push_back(*it);
  }

  RangeArray *common = new RangeArray(output_begin_, output_sz_);
  get_last_block_common(*common, in_blocks, in_byte_propa);
  common->disp_range_array();

  if(common->get_size() != 0) {
    in_block_prpgt.push_back(RangeArraySPtr(common) );
  }

  for(uint32_t i = 0; i < in_block_prpgt.size(); i++) {
    cout << "block " << i << " propagate to: " << endl;
    in_block_prpgt[i]->disp_range_array();
  }

  bool is_dtct       = false;
  uint32_t num_block = 0;
  for (int i = 0; i < in_blocks.get_size(); i++) {
    bool is_last = (i == in_blocks.get_size()-1);
    if(is_last) {
      if(is_dtct) {
        // if previous block is detected, then last block is also detected
        is_dtct = true;
      } else {
        cout << "cbc enc: the last block does not has the pattern" << endl;
        is_dtct = false;
      }
    } else {
      is_dtct = enc_block(i, in_blocks, in_block_prpgt, in_byte_propa);
    }

    if (is_dtct) {
      cout << "detected block: " << i << endl;

      uint32_t input_end = input_.get_end();
      uint32_t block_sz  = in_blocks[i]->get_len();
      input_end += block_sz;
      input_.set_end(input_end);

      num_block++;
    }
  }

  if(input_.get_len() >=0 ) {
    // we have detected blocks
    output_.set_begin(in_block_prpgt[0]->at(0)->get_begin() );
    output_.set_end(in_block_prpgt[0]->at(0)->get_end() );
  }

  uint32_t block_sz = in_blocks[0]->get_len();
  if(in_block_propa_ra[0]->at(0)->get_len() == block_sz * num_block) {
    // the first block propagated range must be len of total detected block sz
    is_dtct = true;
  } else {
    is_dtct = false;
  }

  input_.disp_range();
  output_.disp_range();

  return is_dtct;
}

bool CBCDetector::enc_block(uint32_t idx_block,
                            const RangeArray &in_blocks,
                            const VSPtrRangeArray &in_block_propa_ra,
                            const vector<ByteTaintPropagate *> &in_byte_propa)
{
  if(idx_block == 0) {
    // ToDo
    input_.set_begin(0);
    input_.set_end(0);
  }

  bool has_block_pattern = false;
  has_block_pattern = enc_block_pattern(idx_block, in_blocks, in_block_propa_ra);
  return has_block_pattern;
}

bool CBCDetector::enc_block_pattern(uint32_t idx_block,
                                    const RangeArray &in_blocks,
                                    const VSPtrRangeArray &in_block_propa_ra)
{
  // Pattern 1:n, 1:n, 1:n, etc
  // Compares the propagation of current block and next block, should:
  // 1) Their ends should be identical
  // 2) Their begins should offset with exactly one block sz
  if(idx_block+1 >= in_block_propa_ra.size() ) {
    cout << "cbc enc block pattern: given idx block is invalid" << endl;
    return false;
  }

  Range curr_prpgt(*in_block_propa_ra[idx_block]->at(0) );
  Range next_prpgt(*in_block_propa_ra[idx_block+1]->at(0) );

  curr_prpgt.disp_range();
  next_prpgt.disp_range();

  bool is_idnt_end = (curr_prpgt.get_end() == next_prpgt.get_end() );

  uint32_t block_sz = in_blocks[idx_block]->get_len();
  bool is_offset    = (next_prpgt.get_begin() - curr_prpgt.get_begin() == block_sz);

  if(is_idnt_end &&
      is_offset) {
    return true;
  } else {
    cout << "cbc enc block pattern: given block does not has the pattern" << endl;
    return false;
  }
}

bool CBCDetector::get_last_block_common(RangeArray &common,
                                        const RangeArray &in_blocks,
                                        const std::vector<ByteTaintPropagate *> &in_byte_propa)
{
  uint32_t num_block = in_blocks.get_size();
  uint32_t prev_block_sz = in_blocks[num_block-2]->get_len();
  uint32_t curr_block_sz = in_blocks[num_block-1]->get_len();

  uint32_t i_begin = (num_block-1) * prev_block_sz;
  uint32_t i_end   = i_begin + curr_block_sz;

  for(uint32_t i = i_begin; i < i_end; i++) {
    common.disp_range_array();

    if(common.get_size() == 0) {
      break;
    }

    if(i >= in_byte_propa.size() ) {
      cout << "cbc get last block common: byte index is invlaid" << endl;
      return false;
    }

    ByteTaintPropagate *byte_prpgt = in_byte_propa[i];

    uint32_t addr = byte_prpgt->get_taint_src();
    cout << "addr: " << hex << addr << endl;

    if(byte_prpgt->get_taint_propagate()->get_size() == 0) {
      cout << "cbd get last block common: byte propagation is empty" << endl;
      return false;
    } else {
      common.get_common_range_with_val(*byte_prpgt->get_taint_propagate() );
    }
  }

  return true;
}

bool CBCDetector::analyze_dec(const RangeArray &in_blocks,
                              const VSPtrRangeArray &in_block_propa_ra,
                              const std::vector<ByteTaintPropagate *> &in_byte_propa)
{
  // Repeat analyze_enc()
  VSPtrRangeArray in_block_prpgt;
  for(auto it = in_block_propa_ra.begin(); it != in_block_propa_ra.end(); ++it) {
    in_block_prpgt.push_back(*it);
  }

  RangeArray *common = new RangeArray(output_begin_, output_sz_);
  get_last_block_common(*common, in_blocks, in_byte_propa);
  common->disp_range_array();

  if(common->get_size() != 0) {
    in_block_prpgt.push_back(RangeArraySPtr(common) );
  }

  for(uint32_t i = 0; i < in_block_prpgt.size(); i++) {
    cout << "block " << i << " propagate to: " << endl;
    in_block_prpgt[i]->disp_range_array();
  }

  bool is_dtct = false;
  for (int i = 0; i < in_blocks.get_size(); i++) {
    bool is_last     = (i == in_blocks.get_size()-1);
    bool is_last_sec = (i == in_blocks.get_size()-2);
    if(is_last) {
      is_dtct = dec_last_block(i, in_blocks, in_block_prpgt, in_byte_propa);
    } else if(is_last_sec) {
      is_dtct = dec_block(i, in_blocks, in_block_prpgt, in_byte_propa);
    } else {
      is_dtct = dec_block(i, in_blocks, in_block_prpgt, in_byte_propa);
    }

    if (is_dtct) {
      cout << "detected block: " << i << endl;

      uint32_t block_sz  = in_blocks[i]->get_len();

      uint32_t input_end = input_.get_end();
      input_end += block_sz;
      input_.set_end(input_end);

      uint32_t output_end = output_.get_end();
      output_end += block_sz;
      output_.set_end(output_end);
    }
  }

  input_.disp_range();
  output_.disp_range();

  return is_dtct;
}

bool CBCDetector::dec_block(uint32_t idx_block,
                            const RangeArray &in_blocks,
                            const VSPtrRangeArray &in_block_propa_ra,
                            const std::vector<ByteTaintPropagate *> &in_byte_propa)
{
  if(idx_block == 0) {
    ByteTaintPropagate *first_byte = in_byte_propa[0];
    RangeArray first_byte_prpgt(output_begin_, output_sz_);

    if(first_byte->get_taint_propagate()->get_size() != 0 ) {
      first_byte_prpgt.get_common_range_with_val(*first_byte->get_taint_propagate());
    } else {
      cout << "cbc dec block: first byte has no propagate range" << endl;
      return false;
    }

    first_byte_prpgt.disp_range_array();
    if(first_byte_prpgt.get_size() != 0) {
      output_.set_begin(first_byte_prpgt.at(0)->get_begin() );
      output_.set_end(first_byte_prpgt.at(0)->get_begin() );
    } else {
      cout << "cbc dec block: first byte has no propagate range" << endl;
      return false;
    }
  }

  bool has_block_pattern = false;
//  has_block_pattern = dec_block_pattern(idx_block, in_blocks, in_block_propa_ra);
  has_block_pattern = dec_last_block_pattern(idx_block, in_blocks, in_block_propa_ra);

  if(has_block_pattern) {
    uint32_t block_sz = in_blocks[idx_block]->get_len();
    uint32_t i_begin  = idx_block * block_sz;
    uint32_t i_end    = i_begin + block_sz;

    bool is_dtct = false;
    for(uint32_t i = i_begin; i < i_end; i++) {
      is_dtct = dec_byte(i, idx_block, in_blocks, in_block_propa_ra, in_byte_propa);

      if(!is_dtct) {
        return false;
      }
    }

    return true;
  } else {
    return false;
  }
}

bool CBCDetector::dec_last_block(uint32_t idx_block,
                                 const RangeArray &in_blocks,
                                 const VSPtrRangeArray &in_block_propa_ra,
                                 const std::vector<ByteTaintPropagate *> &in_byte_propa)
{
  // last block only has 1:n block pattern, does not has 1:1 pattern
  bool has_block_pattern = false;
  has_block_pattern = dec_last_block_pattern(idx_block, in_blocks, in_block_propa_ra);
  return has_block_pattern;
}

bool CBCDetector::dec_block_pattern(uint32_t idx_block,
                                    const RangeArray &in_blocks,
                                    const VSPtrRangeArray &in_block_propa_ra)
{
  // cbc dec 1:n pattern to current block:
  // 1) the propagated begin address should begin with current block
  // 2) should propagated larger than blcok size
  // 3) to distinguish with enc, its range end and its next block's propagate
  // range end will be different
  if(idx_block+1 >= in_block_propa_ra.size() ) {
    cout << "cbc dec block pattern: given idx block is invalid" << endl;
    return false;
  }

  if(in_block_propa_ra[idx_block]->get_size() == 0 ||
      in_block_propa_ra[idx_block+1]->get_size() == 0) {
    cout << "cbc dec block pattern: given block propagated range is empty" << endl;
    return false;
  }

  Range curr_prpgt(*in_block_propa_ra[idx_block]->at(0) );
  Range next_prpgt(*in_block_propa_ra[idx_block+1]->at(0) );

  curr_prpgt.disp_range();
  next_prpgt.disp_range();

  bool is_same_begin           = false;
  bool has_block_sz            = false;
  bool has_different_range_end = false;

  is_same_begin = (output_.get_end() == curr_prpgt.get_begin() );

  uint32_t block_sz = in_blocks[idx_block]->get_len();
  has_block_sz = (curr_prpgt.get_len() >= block_sz);

  has_different_range_end = (curr_prpgt.get_end() != next_prpgt.get_end() );

  if(is_same_begin &&
      has_block_sz &&
      has_different_range_end) {
    return true;
  } else {
    cout << "cbc dec block pattern: given block does not has pattern" << endl;
    return false;
  }
}

bool CBCDetector::dec_last_block_pattern(uint32_t idx_block,
                                         const RangeArray &in_blocks,
                                         const VSPtrRangeArray &in_block_propa_ra)
{
  // cbc dec 1:n pattern to current block:
  // 1) the propagated begin address should begin with current block
  // 2) should propagated larger than blcok size
  if(idx_block >= in_block_propa_ra.size() ) {
    cout << "cbc dec block pattern: given idx block is invalid" << endl;
    return false;
  }

  if(in_block_propa_ra[idx_block]->get_size() == 0) {
    cout << "cbc dec block pattern: given block propagated range is empty" << endl;
    return false;
  }

  Range curr_prpgt(*in_block_propa_ra[idx_block]->at(0) );
  curr_prpgt.disp_range();

  bool is_same_begin = false;
  bool has_block_sz  = false;

  is_same_begin = (output_.get_end() == curr_prpgt.get_begin() );

  uint32_t block_sz = in_blocks[idx_block]->get_len();
  has_block_sz = (curr_prpgt.get_len() >= block_sz);

  if(is_same_begin &&
      has_block_sz) {
    return true;
  } else {
    cout << "cbc dec block pattern: given block does not has pattern" << endl;
    return false;
  }
}

bool CBCDetector::dec_byte(uint32_t idx_byte,
                           uint32_t idx_block,
                           const RangeArray &in_blocks,
                           const VSPtrRangeArray &in_block_propa_ra,
                           const vector<ByteTaintPropagate *> &in_byte_propa)
{
  if(idx_byte >= in_byte_propa.size() ) {
    cout << "cbc dec byte: given byte idx is invalid" << endl;
    return false;
  }

  if(idx_block+1 >= in_block_propa_ra.size() ) {
    cout << "cbc dec byte: given block idx is invalid" << endl;
    return false;
  }

  ByteTaintPropagate *byte_prpgt = in_byte_propa[idx_byte];
  if(byte_prpgt->get_taint_propagate()->get_size() == 0) {
    cout << "cbc dec byte: given byte propagation is empty" << endl;
    return false;
  }

  RangeArray common(output_begin_, output_sz_);
  common.get_common_range_with_val(*byte_prpgt->get_taint_propagate() );
  common.disp_range_array();

  if(common.get_size() == 0) {
    cout << "cbc dec byte: given byte propagation is empty" << endl;
    return false;
  }

  uint32_t block_sz    = in_blocks[idx_block]->get_len();
  uint32_t byte_offset = idx_byte % block_sz;
  uint32_t next_block_begin = in_block_propa_ra[idx_block+1]->at(0)->get_begin();
  for(uint32_t i = 0; i < common.get_size(); i++) {
    uint32_t curr_byte_prpgt = common[i]->get_begin();
    for(uint32_t j = 0; j < common[i]->get_len(); j++) {

      if(curr_byte_prpgt >= next_block_begin &&
          (curr_byte_prpgt - next_block_begin) == byte_offset) {
        return true;
      }

      curr_byte_prpgt++;
    }
  }

  cout << "cbc dec byte: given does not has the pattern." << endl;
  return false;
}