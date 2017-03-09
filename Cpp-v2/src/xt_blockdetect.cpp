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

        int idx_outter;
        for(idx_outter = begin_byte; idx_outter < end_byte; idx_outter++){
           int idx_inner;

           common.disp_range_array();
           old_common.disp_range_array();

           for(idx_inner = idx_outter; idx_inner < end_byte; idx_inner++){
               // Debug
               if(idx_inner == 15){
                   cout << "idx_inner: " << idx_inner << endl;
               }

               ByteTaintPropagate *byte_taint_propagate = buf_taint_propagate[idx_inner];

               byte_taint_propagate->get_taint_propagate()->disp_range_array();
               common.get_common_range(*byte_taint_propagate->get_taint_propagate() );
               common.disp_range_array();

               // remove common ranges that are smaller than the current
               // processed buffer: i - begin
               unsigned int min_block_sz = max(idx_outter - begin_byte + 1, 4);
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
           } // end inner loop
           begin_byte++;
           end_byte = min(begin_byte + WINDOW_SIZE, in_byte_sz);
        } // end outter loop
    }
}

