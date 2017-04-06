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

  analyze_enc(in_blocks, in_block_propa_ra, in_byte_propa);
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

  bool is_dtct = false;
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
    }
  }

  if(input_.get_len() >=0 ) {
    // we have detected blocks
    output_.set_begin(in_block_prpgt[0]->at(0)->get_begin() );
    output_.set_end(in_block_prpgt[0]->at(0)->get_end() );
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
  if(idx_block+1 >= in_blocks.get_size() ) {
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
