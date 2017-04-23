#include "xt_blockdetector.h"
#include <iostream>

using namespace std;

BlockDetector::BlockDetector(uint32_t in_begin, uint32_t in_len,
                             uint32_t out_begin, uint32_t out_len)
{
  in_begin_   = in_begin;
  in_len_     = in_len;
  out_begin_  = out_begin;
  out_len_    = out_len;
}

void
BlockDetector::detect_block(RangeArray &in_blocks,
                            VSPtrRangeArray &in_blocks_prpgt,
                            const vector<TaintPropagate *>& in_prpgt_ra_res)
{
  detect_block_not_handle_last(in_blocks, in_blocks_prpgt, in_prpgt_ra_res);
}

void
BlockDetector::detect_block_not_handle_last(RangeArray &in_blocks,
                                            VSPtrRangeArray &in_blocks_prpgt,
                                            const vector<TaintPropagate *>& in_prpgt_ra_res)
{
  uint32_t bk_begin_byte  = 0;
  uint32_t bk_end_byte    = in_len_;

  uint32_t buf_size       = in_len_;
  uint32_t accumu_bk_sz   = 0;
  uint32_t bk_sz          = 0;

  // loops until reaching begin of potential last blcok
  while(buf_size - accumu_bk_sz > bk_sz) {
    RangeArray common(out_begin_, out_len_);
    RangeArray old_common;

    uint32_t i = bk_begin_byte;
    for(; i < bk_end_byte; i++) {
      common.print_range_array();
      old_common.print_range_array();

      if (accumu_bk_sz == 0) {
        // Handles block begins, for a potential block, uses the first
        // two byte propagations to setup the common ranges
        bool is_init  = init_block(common, i, i+1, in_prpgt_ra_res);

        if(!is_init
           || common.get_size() == 0) {
          cout << "potential block first two bytes have no common." << endl;
          bk_begin_byte = i;
          buf_size--;
          break;
        } else {
          // inits block successfully
          old_common = common;
          accumu_bk_sz++;
        }
      } else {
        bool is_ext = extend_block(common, i, in_prpgt_ra_res);

        if(!is_ext) {
          save_block(in_blocks, in_blocks_prpgt, bk_begin_byte, accumu_bk_sz, old_common);

          bk_begin_byte = i;
          buf_size      -= accumu_bk_sz;
          accumu_bk_sz  = 0;
          break;

        } else {
          // extends the current byte successfully
          if(is_block_end(common, old_common, accumu_bk_sz) ) {
            save_block(in_blocks, in_blocks_prpgt, bk_begin_byte, accumu_bk_sz, old_common);

            bk_begin_byte   = i;
            buf_size        -= accumu_bk_sz;
            accumu_bk_sz    = 0;
            break;

          } else {
            old_common = common;
            accumu_bk_sz++;
          }
        } // end if is_ext
      }
    } // end for loop

    // updates block size if any
    if(in_blocks.get_size() > 0) {
      uint32_t num_bk = in_blocks.get_size();
      bk_sz           = in_blocks.at(num_bk-1)->get_len();
    }
  } // end while

  in_blocks.add_range(bk_begin_byte, buf_size);
}

bool
BlockDetector::init_block(RangeArray &common,
                          uint32_t idx_byte_a,
                          uint32_t idx_byte_b,
                          const vector<TaintPropagate *>& in_prpgt_ra_res)
{

}

bool
BlockDetector::extend_block(RangeArray &common,
                            uint32_t idx_byte,
                            const vector<TaintPropagate *>& in_prpgt_ra_res)
{

}

bool
BlockDetector::save_block(RangeArray      &in_blocks,
                          VSPtrRangeArray &in_blocks_prpgt,
                          uint32_t        bk_begin_idx,
                          uint32_t        accumu_bk_sz,
                          RangeArray      &common)
{

}

bool
BlockDetector::is_block_end(RangeArray &common,
                            RangeArray &old_common,
                            uint32_t   accumu_b_sz)
{

}
