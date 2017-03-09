#include "xt_blockdetect.h"

#include <iostream>
using namespace std;

void BlockDetect::detect_block_size(Blocks &blocks,
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
