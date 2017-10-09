#include "xt_blockdetect.h"
#include "xt_blockmodedetector.h"

#include <iostream>
using namespace std;


BlockDetect::BlockDetect(unsigned int out_begin_addr, unsigned int out_len)
{
    out_begin_addr_ = out_begin_addr;
    out_len_        = out_len;
}

BlockDetect::BlockDetect(uint32_t in_begin_addr,
                         uint32_t in_len,
                         uint32_t out_begin_addr,
                         uint32_t out_len) {
  in_begin_addr_ = in_begin_addr;
  in_len_        = in_len;
  out_begin_addr_= out_begin_addr;
  out_len_       = out_len;
}

void BlockDetect::detect_block_size(RangeArray &input_blocks,
                                    VSPtrRangeArray &input_block_propa,
                                    vector<ByteTaintPropagate *> &buf_taint_propagate) {
//  detect_block_size_with_val(buf_taint_propagate);
  detect_block_size_handling_last_block(input_blocks, input_block_propa,
                                        buf_taint_propagate);
}

void BlockDetect::detect_block_size_ori(Blocks &blocks,
                                        vector<ByteTaintPropagate *> &buf_taint_propagate,
                                        unsigned int in_byte_sz,
                                        unsigned int out_addr,
                                        unsigned int out_byte_sz)
{
    int begin_byte = 0;
    int end_byte   = in_byte_sz;

    while(end_byte - begin_byte > 0){
        // Initially common range cover full user address space
        // Need to change to kernel address later
        //
        // Instead of covering full address space, we use the target (out)
        // buffer addr and len.
        // Cipher Xray seems not using the out buffer info, interesting
        RangeArray common(out_addr, out_byte_sz);
        // RangeArray common(MIN_ADDRESS, MAX_ADDRESS - MIN_ADDRESS + 1);
        RangeArray old_common;

        int idx;
        for(idx = begin_byte; idx < end_byte; idx++){

           common.disp_range_array();
           old_common.disp_range_array();

           ByteTaintPropagate *byte_taint_propagate = buf_taint_propagate[idx];

           byte_taint_propagate->get_taint_propagate()->disp_range_array();
           common.get_common_range(*byte_taint_propagate->get_taint_propagate() );
           common.disp_range_array();

           // remove common ranges that are smaller than the current
           // processed buffer: idx - begin
           // Also, minimum block size is 8 bytes
           unsigned int min_block_sz = max(idx - begin_byte + 1, 8);
           for(int j = 0; j < common.get_size(); ){
               if(common[j]->get_len() < min_block_sz ){
                   common.remove_range(j);
                   continue;
               }
               j++;
           }

           if(common.get_size() == 0 && old_common.get_size() != 0){
               old_common.disp_range_array();
           }

           old_common = common;
           old_common.disp_range_array();

           begin_byte++;
           end_byte = min(begin_byte + WINDOW_SIZE, in_byte_sz);
        } // end for loop
    }
}

// Currently not consider the input buffer size is very large, i.e., > 100 bytes
void BlockDetect::detect_block_size_alter(Blocks &blocks,
                                          vector<ByteTaintPropagate *> &buf_taint_propagate,
                                          unsigned int in_byte_sz,
                                          unsigned int out_addr,
                                          unsigned int out_byte_sz)
{
    unsigned block_begin = 0;
    unsigned block_end   = in_byte_sz;

    unsigned int buf_win = in_byte_sz;
    unsigned int accumu_block_win = 0;

    while( buf_win - accumu_block_win > 0){
        unsigned min_block_sz = 8;

        // Initially common range cover full user address space
        // Need to change to kernel address later
        //
        // Instead of covering full address space, we use the target (out)
        // buffer addr and len.
        // Cipher Xray seems not using the out buffer info, interesting
        RangeArray common(out_addr, out_byte_sz);
        // RangeArray common(MIN_ADDRESS, MAX_ADDRESS - MIN_ADDRESS + 1);
        RangeArray old_common;

        for(int idx_byte = block_begin; idx_byte < block_end; idx_byte++){
           common.disp_range_array();
           old_common.disp_range_array();

           ByteTaintPropagate *byte_taint_propagate = buf_taint_propagate[idx_byte];
           unsigned int byte_addr = byte_taint_propagate->get_taint_src();
           cout << "current byte addr: " << hex << byte_addr << endl;
           byte_taint_propagate->get_taint_propagate()->disp_range_array();


           common.get_common_range(*byte_taint_propagate->get_taint_propagate() );
           common.disp_range_array();

           rm_minimum_range(common, min_block_sz);

           // Only for cbc dec mode
           if(common.get_size() == 0){
               if(accumu_block_win < min_block_sz){
                   // The taint source byte propagation result has NO common ranges
                   // with the targeted (output) buffer range,
                   // advance to next taint source byte
                   block_begin++;
               }else{
                   // find a valid block:
                   //   begin: block_begin
                   //   end:   block_begin + accumu_block_sz
                   blocks.push_back(RangeSPtr(new Range(block_begin, accumu_block_win) ) );

                   // advances to next taint source byte
                   // no need to plus extra 1
                   block_begin = idx_byte;
               }
               buf_win = buf_win - accumu_block_win;
               accumu_block_win = 0;
               break;
           }

           // for cbc enc mode
           int len_common = common[0]->get_len();
           int len_old_common = old_common[0]->get_len();
           if( (len_old_common - len_common) == accumu_block_win ){
               if(accumu_block_win < min_block_sz){
                   block_begin++;
               }else {
                   blocks.push_back(RangeSPtr(new Range(block_begin, accumu_block_win) ) );
                   block_begin = idx_byte;
               }
               buf_win = buf_win - accumu_block_win;
               accumu_block_win = 0;
               break;
           }

           old_common = common;
           old_common.disp_range_array();

           accumu_block_win++;
        } // end for

        if(accumu_block_win >= min_block_sz){
            // find a valid block
            blocks.push_back(RangeSPtr(new Range(block_begin, accumu_block_win) ) );

            buf_win -= accumu_block_win;
            accumu_block_win = 0;
        }

    } // end while
}

void BlockDetect::detect_block_sz_small_win(Blocks &blocks,
                                 vector<ByteTaintPropagate *> &buf_taint_propagate,
                                 unsigned int in_byte_sz,
                                 unsigned int out_addr,
                                 unsigned int out_byte_sz)
{
    unsigned int b_begin_byte = 0;
    unsigned int b_end_byte   = in_byte_sz;

    unsigned int buf_sz       = in_byte_sz;
    unsigned int accumu_b_sz  = 0;

    while(buf_sz - accumu_b_sz > 0){
        // Initially common range cover full user address space
        // Need to change to kernel address later
        //
        // The reason why not using the output range, is because output range
        // only works for the last cipher. But consider a mix cipher:
        // first enc then dec, the output range only for the dec, but not
        // the enc

        RangeArray common(out_addr, out_byte_sz);
        // RangeArray common(MIN_ADDRESS, MAX_ADDRESS - MIN_ADDRESS + 1);
        RangeArray prev_common;

        int i = b_begin_byte;
        for(; i < b_end_byte; i++){
            ByteTaintPropagate *firbyte_taint_propa = buf_taint_propagate[i];
            unsigned int firstbyte_addr = firbyte_taint_propa->get_taint_src();
            cout << "propcessing byte addr: " << hex << firstbyte_addr << endl;

            // RangeArray curr_byte_ra =
            //   *firbyte_taint_propa->get_taint_propagate();
            // curr_byte_ra.disp_range_array();

            if(firbyte_taint_propa->get_taint_propagate()->get_size() == 0) {
              save_block(accumu_b_sz, blocks, b_begin_byte, i);

                if(accumu_b_sz == 0) {
                    buf_sz--;
                } else {
                    buf_sz      -= accumu_b_sz;
                }
                accumu_b_sz = 0;
                break;
            }

          //            if(curr_byte_ra.get_size() == 0) {
          //                save_block(accumu_b_sz, blocks, b_begin_byte, i);
          //
          //                if(accumu_b_sz == 0) {
          //                    buf_sz--;
          //                } else {
          //                    buf_sz      -= accumu_b_sz;
          //                }
          //                accumu_b_sz = 0;
          //                break;
          //            }

            common.get_common_range(*firbyte_taint_propa->get_taint_propagate() );
            common.disp_range_array();

            if(accumu_b_sz == 0 && common.get_size() == 0) {
                b_begin_byte++;
                buf_sz--;
                break;
            }

            if(accumu_b_sz == 0){
                // For a potential block, uses the first two bytes of the block
                // to determin the common propagate range
                ByteTaintPropagate *secbyte_taint_propa = buf_taint_propagate[i+1];
                common.get_common_range(*secbyte_taint_propa->get_taint_propagate() );

                // filter out minimum size block
                rm_minimum_range(common, MIN_BLOCK_SZ);
            }

            common.disp_range_array();
            prev_common.disp_range_array();

            // If detects the current byte common range is different from previous bytes'
            // range, then we assume it is a byte in next block.
            // The assumption is all bytes belongs to the same block should have same
            // common range.
            //
            // We loose the constrain, only if the first range is identical is enough
            if(accumu_b_sz != 0 &&
               !(common[0]->get_begin() == prev_common[0]->get_begin() &&
               common[0]->get_len() == prev_common[0]->get_len() ) ) {
                cout << "detecting block sz: find a block end" << endl;
                save_block(accumu_b_sz, blocks, b_begin_byte, i);

                buf_sz -= accumu_b_sz;
                accumu_b_sz = 0;
                break;
            }


            // if(accumu_b_sz != 0 &&
            //    !common.is_identical(prev_common) ){
            //     cout << "detecting block sz: find a block end" << endl;
            //     save_block(accumu_b_sz, blocks, b_begin_byte, i);

            //     buf_sz -= accumu_b_sz;
            //     accumu_b_sz = 0;
            //     break;
            // }

            prev_common = common;
            accumu_b_sz++;
        } // end for

    } // end while
    if(accumu_b_sz >= MIN_BLOCK_SZ){
        blocks.push_back(RangeSPtr(new Range(b_begin_byte, b_end_byte) ) );
    }
}

bool BlockDetect::detect_mode_type(const RangeArray input_blocks,
                                   const VSPtrRangeArray input_block_propa,
                                   const vector<ByteTaintPropagate *> &v_in_propagate) {
  bool is_det = detect_mode_type_with_val(input_blocks, input_block_propa,
                                   v_in_propagate);
  return is_det;
}

void BlockDetect::detect_mode_type_ori(vector<ByteTaintPropagate *> &v_in_propagate,
                                       Blocks &blocks)
{
    DetectFactory &det_fac = DetectFactory::get_instance();

    // We don't know which mode, try all
    det_fac.begin();

    while(!det_fac.at_end() ){
        ModeDetect *detector = det_fac.get_detector();
        cout << detector->get_mode_name() << endl;

        if(detector->analyze_mode(v_in_propagate, blocks) ){

        }

        det_fac.next();
    }

    // Above code seems not working, debug here
    CBCDetect &det_cbc = CBCDetect::get_instance();
    // det_cbc.analyze_mode(v_in_propagate, blocks);
    // det_cbc.analyze_mode_alter(v_in_propagate, blocks, out_begin_addr_, out_len_);
    det_cbc.analyze_mode_improve(v_in_propagate, blocks, out_begin_addr_, out_len_);

}

bool BlockDetect::detect_mode_type_with_val(const RangeArray input_blocks,
                                            const VSPtrRangeArray input_block_propa,
                                            const vector<ByteTaintPropagate *> &v_in_propagate) {
//  if(in_blocks_.get_size() == 0) {
  if(input_blocks.get_size() == 0) {
    cout << "no blocks found..." << endl;
    return false;
  } else if(input_blocks.get_size() == 1) {
    cout << "only one block found..." << endl;
    return false;
  }

  input_blocks.disp_range_array();
  // We don't use singleton factory, buggy
  // DetectFactory &det_fac = DetectFactory::get_instance();
  // det_fac.count_num_detector();

  // Detects ECB
  // ECBDetect &det_ecb = ECBDetect::get_instance();
  // det_ecb.analyze_ecb_mode(v_in_propagate, get_in_blocks(), get_out_propa_ra());

  CFBDetector det_cfb;
  return det_cfb.analyze_mode(input_blocks, input_block_propa, v_in_propagate);
//  return det_cfb.analyze_mode(in_blocks_, propa_out_ra_, v_in_propagate);
}

void BlockDetect::detect_block_size_with_val(
    vector<ByteTaintPropagate *> &buf_taint_propagate) {

  uint32_t b_begin_byte = 0;
  uint32_t b_end_byte = in_len_;

  uint32_t buf_sz = in_len_;
  uint32_t accumu_b_sz = 0;

  RangeArray last_common;

  while (buf_sz - accumu_b_sz > 0) {
    // Initially common range cover full address space of output range
    RangeArray common(out_begin_addr_, out_len_);
    RangeArray prev_common;

    uint32_t i = b_begin_byte;
    for (; i < b_end_byte; i++) {
      common.disp_range_array();
      prev_common.disp_range_array();

      common.disp_byte_val_map_array();
      prev_common.disp_byte_val_map_array();

      if(accumu_b_sz == 0) {
        // Handles block begins
        // For a potential block, uses the first two byte propagations to
        // setup the common ranges
        bool is_init = init_block(common, i, i + 1, buf_taint_propagate);

        if(!is_init ||
            common.get_size() == 0) {
          cout << "Potential block first two bytes have no common." << endl;
          b_begin_byte = i;
          buf_sz--;
          break;
        } else {
          // Init block successfully
          prev_common = common;
          accumu_b_sz++;
        }
      } else {
        bool is_ext = extend_block(common, i, buf_taint_propagate);

        if(!is_ext) {
          save_block_with_val(b_begin_byte, accumu_b_sz, prev_common);

          b_begin_byte = i;
          buf_sz -= accumu_b_sz;
          accumu_b_sz = 0;
          break;
        } else {
          // extend the current byte to current common range successfully,
          // needs to test if the block ends
          if (is_block_end(common, prev_common, accumu_b_sz)) {
            save_block_with_val(b_begin_byte, accumu_b_sz, prev_common);

            b_begin_byte = i;
            buf_sz -= accumu_b_sz;
            accumu_b_sz = 0;
            break;
          } else {
            // not end, continue
            prev_common = common;
            accumu_b_sz++;
          }
        }
      }

//      // Iterate each byte to see if they have same propagated range
//      ByteTaintPropagate *first_byte_propa = buf_taint_propagate[i];
//
//      uint32_t first_byte_addr = first_byte_propa->get_taint_src();
//      cout << "byte addr: " << hex << first_byte_addr << endl;
//
//      first_byte_propa->get_taint_propagate()->disp_range_array();
//
//      // ToDo
//      if (first_byte_propa->get_taint_propagate()->get_size() == 0) {
//        // handle byte propagation is empty case
//        cout << "Block detect: byte propagation is empty..." << endl;
//        return;
//      }
//
//      common.get_common_range_with_val(*first_byte_propa->get_taint_propagate());
//      common.disp_range_array();
//      // common.disp_byte_val_map_array();
//
//      // ToDo
//      if (common.get_size() == 0) {
//        // handle case the common range is empty
//        cout << "After intersect with current range array, common is empty"
//             << endl;
//      }
//
//      /*if(accumu_b_sz == 0) {
//        // Do we need it?
//        // A potential block, uses first two bytes to determine the common
//        // propagate range
//        ByteTaintPropagate *sec_byte_propa = buf_taint_propagate[i+1];
//        common.get_common_range_with_val(*sec_byte_propa->get_taint_propagate());
//        common.disp_range_array();
//        common.disp_byte_val_map_array();
//      }*/
//
//      common.disp_range_array();
//      prev_common.disp_range_array();
//      common.disp_byte_val_map_array();
//      prev_common.disp_byte_val_map_array();
//
//      // handles case than ends a block
//      if(is_block_end(common, prev_common, accumu_b_sz) ) {
//        save_block_with_val(b_begin_byte, accumu_b_sz, prev_common);
//
//        b_begin_byte = i;
//        buf_sz       -= accumu_b_sz;
//        accumu_b_sz  = 0;
//        break;
//      }
//
//      prev_common = common;
//      accumu_b_sz++;

    }

    last_common = prev_common;
  } // end while

  // save the last block if any
  save_block_with_val(b_begin_byte, accumu_b_sz, last_common);
}

void BlockDetect::detect_block_size_handling_last_block(RangeArray &input_blocks,
                                                        VSPtrRangeArray &input_block_propa,
                                                        vector<ByteTaintPropagate *> &buf_taint_propagate)
{
  uint32_t b_begin_byte = 0;
  uint32_t b_end_byte = in_len_;

  uint32_t buf_sz = in_len_;
  uint32_t accumu_b_sz = 0;

//  RangeArray last_common;

  uint32_t block_sz = 0;

  // loops until reaching the begin of potential last block
  while (buf_sz - accumu_b_sz > block_sz) {
    // Initially common range cover full address space of output range
    RangeArray common(out_begin_addr_, out_len_);
    RangeArray prev_common;

    uint32_t i = b_begin_byte;
    for (; i < b_end_byte; i++) {
      if(i == 16) {
        cout << "i is 16" << endl;
      }

      common.disp_range_array();
      prev_common.disp_range_array();

      common.disp_byte_val_map_array();
      prev_common.disp_byte_val_map_array();

      if(accumu_b_sz == 0) {
        // Handles block begins
        // For a potential block, uses the first two byte propagations to
        // setup the common ranges
        bool is_init = init_block(common, i, i + 1, buf_taint_propagate);

        if(!is_init ||
            common.get_size() == 0) {
          cout << "Potential block first two bytes have no common." << endl;
          b_begin_byte = i;
          buf_sz--;
          break;
        } else {
          // Init block successfully
          prev_common = common;
          accumu_b_sz++;
        }
      } else {
        bool is_ext = extend_block(common, i, buf_taint_propagate);

        if(!is_ext) {
          store_block(input_blocks, input_block_propa, b_begin_byte,
                      accumu_b_sz, prev_common);
//          save_block_with_val(b_begin_byte, accumu_b_sz, prev_common);

          b_begin_byte = i;
          buf_sz -= accumu_b_sz;
          accumu_b_sz = 0;
          break;
        } else {
          // extend the current byte to current common range successfully,
          // needs to test if the block ends
          if (is_block_end(common, prev_common, accumu_b_sz)) {
            store_block(input_blocks, input_block_propa, b_begin_byte,
                      accumu_b_sz, prev_common);
//            save_block_with_val(b_begin_byte, accumu_b_sz, prev_common);

            b_begin_byte = i;
            buf_sz -= accumu_b_sz;
            accumu_b_sz = 0;
            break;
          } else {
            // not end, continue
            prev_common = common;
            accumu_b_sz++;
          }
        }
      }
    }

    // update block size if any
    if(input_blocks.get_size() > 0) {
      uint32_t num_block = input_blocks.get_size();
      block_sz = input_blocks.at(num_block-1)->get_len();
    }
//    if(in_blocks_.get_size() > 0) {
//      uint32_t num_block = in_blocks_.get_size();
//      block_sz = in_blocks_.at(num_block - 1)->get_len();
//    }

//    last_common = prev_common;
  } // end while

  cout << "curr begin byte: " << b_begin_byte
       << " buf size: " << buf_sz << endl;

  for(int i = b_begin_byte; i < b_begin_byte+buf_sz; i++) {
    RangeArray common(out_begin_addr_, out_len_);
    ByteTaintPropagate *byte = buf_taint_propagate[i];

    if (byte->get_taint_propagate()->get_size() == 0) {
      continue;
    }

    cout << "byte addr: " << hex << byte->get_taint_src() << endl;
    cout << "before intersecting current byte: " << endl;
    common.disp_range_array();

    common.get_common_range_with_val(*byte->get_taint_propagate());
    cout << "after intersecting current byte: " << endl;
    common.disp_range_array();
  }

  // save the last block if any
  input_blocks.add_range(b_begin_byte, buf_sz);
//  in_blocks_.add_range(b_begin_byte, buf_sz);
//  save_block_with_val(b_begin_byte, accumu_b_sz, last_common);
}

bool BlockDetect::init_block(RangeArray &common,
                             uint32_t idx_byte_a,
                             uint32_t idx_byte_b,
                             vector<ByteTaintPropagate *> &buf_taint_propagate)
{
  uint32_t buf_sz = buf_taint_propagate.size();
  if(idx_byte_a > buf_sz - 1 ||
      idx_byte_b > buf_sz - 1) {
    cout << "error: intersect common range: given idx is invalid." << endl;
    return false;
  }

  ByteTaintPropagate *a = buf_taint_propagate[idx_byte_a];
  ByteTaintPropagate *b = buf_taint_propagate[idx_byte_b];

  if(a->get_taint_propagate()->get_size() == 0 ||
      b->get_taint_propagate()->get_size() == 0) {
    cout << "intersect common range: give bytes propagations are empty."
         << endl;
    return false;
  }

  a->get_taint_propagate()->disp_range_array();
  b->get_taint_propagate()->disp_range_array();

  common.get_common_range_with_val(*a->get_taint_propagate() );
  if(common.get_size() == 0) {
    cout << "intersect common range: give bytes propagations are empty."
         << endl;
    return false;
  } else {
    common.get_common_range_with_val(*b->get_taint_propagate());
  }

  return true;
}

bool BlockDetect::extend_block(RangeArray &common,
                               uint32_t idx_byte,
                               vector<ByteTaintPropagate *> &buf_taint_propagate)
{
  uint32_t buf_sz = buf_taint_propagate.size();
  if(idx_byte > buf_sz - 1) {
    cout << "error: extend block: given idx is invalid." << endl;
    return false;
  }

  ByteTaintPropagate *byte = buf_taint_propagate[idx_byte];

  if(byte->get_taint_propagate()->get_size() == 0) {
    cout << "extend block: give bytes propagations are empty."
         << endl;
    return false;
  }

  cout << "extend block: byte addr: " << hex
      << byte->get_taint_src() << endl;
  cout << "before intersecting current byte: " << endl;
  common.disp_range_array();

  common.get_common_range_with_val(*byte->get_taint_propagate() );

  cout << "after intersecting current byte: " << endl;
  common.disp_range_array();

  return true;
}

bool BlockDetect::is_block_end(RangeArray &common,
                               RangeArray &prev_common,
                               uint32_t accumu_b_sz) {
  if(accumu_b_sz == 0) {
    // begin of a potential block, common and prev_common will be different
    return false;
  }

  if(prev_common.get_size() == 0 ||
      common.get_size() == 0) {
    // if prev is non empty, and current is, indicating they are different,
    // which should be end of a block
    return true;
    // return false;
  }

  prev_common.disp_range_array();
  common.disp_range_array();

  // Determines if 1st range of prev_common and common are identical,
  // to determine if it same block
  // Only compared the begin due to it happens in bf test:
  // Prev:
  // begin addr: 804c080 len: 9 bytes
  // begin addr: 804c0a8 len: 8 bytes
  // Common:
  // begin addr: 804c080 len: 8 bytes
  // begin addr: 804c0a8 len: 8 bytes
  // This is valid
  if(prev_common[0]->get_begin() == common[0]->get_begin() &&
      common[0]->get_len() >= 8) {
    return false;
  } else {
    return true;
  }

  /*
  if(prev_common[0]->is_identical_range(*common[0]) ) {
    return false;
  } else {
    return true;
  }
  */
}

void BlockDetect::rm_minimum_range(RangeArray &ra, unsigned int minimum_range)
{
    for(int i = 0; i < ra.get_size(); ) {
        if(ra[i]->get_len() < minimum_range){
            ra.remove_range(i);
            continue;
        }
        i++;
    }
}

bool BlockDetect::save_block(unsigned accumu_b_sz, Blocks &blocks,
                             unsigned int &b_begin_byte, int i_byte)
{
    if(accumu_b_sz < MIN_BLOCK_SZ){
        b_begin_byte++;
    }else{
        blocks.push_back(RangeSPtr(new Range(b_begin_byte, accumu_b_sz) ) );
        // advances to next taint source byte, no need to plus extra 1
        b_begin_byte = i_byte;
    }
}

bool BlockDetect::save_block_with_val(uint32_t b_begin_idx,
                                      uint32_t accumu_b_sz,
                                      RangeArray &ra_common) {
  if(accumu_b_sz < MIN_BLOCK_SZ) {
    return false;
  } else {
    in_blocks_.add_range(b_begin_idx, accumu_b_sz);
    in_blocks_.disp_range_array();

    RangeArray *propa_ra = new RangeArray();
    for(uint32_t i = 0; i < ra_common.get_size(); i++) {
      propa_ra->add_range(*ra_common[i]);
    }
    propa_out_ra_.push_back(RangeArraySPtr(propa_ra) );

    propa_ra->disp_range_array();
    propa_ra->disp_byte_val_map_array();

    for(uint32_t i=0; i < propa_out_ra_.size(); i++) {
      propa_out_ra_[i]->disp_range_array();
      propa_out_ra_[i]->disp_byte_val_map_array();
    }

    return true;
  }
}

bool BlockDetect::store_block(RangeArray &input_blocks,
                              VSPtrRangeArray &input_block_propa,
                              uint32_t b_begin_idx,
                              uint32_t accumu_b_sz,
                              RangeArray &ra_common)
{
   if(accumu_b_sz < MIN_BLOCK_SZ) {
    return false;
  } else {
    input_blocks.add_range(b_begin_idx, accumu_b_sz);
    input_blocks.disp_range_array();
     ra_common.disp_range_array();

    RangeArray *propa_ra = new RangeArray();
    for(uint32_t i = 0; i < ra_common.get_size(); i++) {
      propa_ra->add_range(*ra_common[i]);
    }
    input_block_propa.push_back(RangeArraySPtr(propa_ra) );

    propa_ra->disp_range_array();
    propa_ra->disp_byte_val_map_array();

    for(uint32_t i=0; i < input_block_propa.size(); i++) {
      input_block_propa[i]->disp_range_array();
      input_block_propa[i]->disp_byte_val_map_array();
    }

    return true;
  }
}