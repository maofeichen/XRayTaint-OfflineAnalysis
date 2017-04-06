#include "xt_cbcdetector.h"
#include <vector>
#include <iostream>

using namespace std;

bool CBCDetector::analyze_mode(const RangeArray &in_blocks,
                               const VSPtrRangeArray &in_block_propa_ra,
                               const vector<ByteTaintPropagate *> &in_byte_propa)
{
  if(!valid_input(in_blocks, in_block_propa_ra, in_byte_propa) ) {
    return false;
  }

  cout << "blocks detected: " << endl;
  in_blocks.disp_range_array();

  cout << "blocks common propagated ranges: " << endl;
  for (int i = 0; i < in_block_propa_ra.size(); ++i) {
    cout << "block: " << i << " propagates to: " << endl;
    in_block_propa_ra[i]->disp_range_array();
  }


}
