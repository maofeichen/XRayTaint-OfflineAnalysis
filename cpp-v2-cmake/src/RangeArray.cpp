#include "RangeArray.h"
#include <cassert>
#include <iostream>

using namespace std;

Range::Range() {
  begin_addr_ = 0;
  end_addr_   = 0;
}

Range::Range(const Range &r) {
  begin_addr_ = r.get_begin();
  end_addr_   = r.get_end();

  for(auto it = r.get_byte_val_map().begin(); it != r.get_byte_val_map().end
      (); ++it) {
    byte_val_map_.insert(*it);
  }
}

Range::Range(uint32_t begin_addr, uint32_t len, uint32_t val) {
  if(len != 1) {
    cout << "err: init range, len is not 1 byte" << endl;
  }
  begin_addr_ = begin_addr;
  end_addr_   = begin_addr + len;
  byte_val_map_.insert(pair<uint32_t, uint32_t >(begin_addr, val) );
}

Range::Range(uint32_t begin_addr,
             uint32_t len,
             const multimap<uint32_t, uint32_t> &byte_val_map) {
  begin_addr_ = begin_addr;
  end_addr_   = begin_addr + len;
  for(auto it = byte_val_map.begin(); it != byte_val_map.end(); ++it) {
    byte_val_map_.insert(*it);
  }
}

void Range::set_byte_val_map(std::multimap<uint32_t, uint32_t> &byte_val_map) {
  byte_val_map_.clear();
  for(auto it = byte_val_map.begin(); it != byte_val_map.end(); ++ it) {
    byte_val_map_.insert(*it);
  }
}

void Range::add_byte_val(uint32_t byte_addr, uint32_t val) {
  byte_val_map_.insert(pair<uint32_t, uint32_t >(byte_addr, val) );
}

void Range::disp_byte_val_map() {
  for(auto it = byte_val_map_.begin(); it != byte_val_map_.end(); ++it) {
    cout << "addr: " << hex << it->first << " val: " << hex << it->second
         << endl;
  }
}

void Range::disp_range() const
{
    cout << "begin addr: " << hex << begin_addr_
            << " len: " << dec << end_addr_ - begin_addr_ << endl;
}

bool Range::has_range(unsigned int begin_addr, unsigned int len)
{
    if( (begin_addr_ <= begin_addr) &&
        (end_addr_ >= begin_addr + len) ) {
        return true;
    }else {
        return false;
    }
}

bool Range::is_continuous_range(Range &r) {
  if(end_addr_ == r.get_begin() ) {
    return true;
  } else {
    return false;
  }
}

bool Range::is_identical_range(Range &r) {
  if(begin_addr_ == r.get_begin() &&
      end_addr_ == r.get_end() ) {
    // Not only ranges should be same, but their each byte value should be same
    if(is_identical_byte_val_map(r.get_byte_val_map() ) ) {
      return true;
    } else {
      return false;
    }
  }else {
    return false;
  }
}

bool Range::is_identical_byte_val_map(const multimap<uint32_t, uint32_t> &byte_val_map) {
  if(byte_val_map.empty() ) {
    return false;
  }

  for(multimap<uint32_t,uint32_t>::const_iterator it = byte_val_map.begin();
      it != byte_val_map.end(); ++it) {
    uint32_t addr = it->first;  // addr is key
    uint32_t val  = it->second;

    // each <byte addr> in byte_val_map, must be found in byte_val_map_
    pair<multimap<uint32_t,uint32_t>::iterator,
         multimap<uint32_t,uint32_t>::iterator> ret_find;
    ret_find = byte_val_map_.equal_range(addr);

    bool is_found = false;
    for(multimap<uint32_t,uint32_t>::iterator it_to_find = ret_find.first;
        it_to_find != ret_find.second; ++it_to_find) {
      uint32_t to_comp_val = it_to_find->second;
      if(val == to_comp_val) {
        is_found = true;
        break;
      }
    }

    if(!is_found) {
      return false;
    }
  }

  return true;
}

RangeArray::RangeArray() {init(); }

RangeArray::RangeArray(Range &r) {
  init();
  add_range(r);
}

RangeArray::RangeArray(const Range &r)
{

}

RangeArray::RangeArray(unsigned int begin_addr, unsigned int len)
{
    init();
    add_range(begin_addr, len);
}

RangeArray::~RangeArray() {
    reset();
    delete[] ref_rray_;
}

Range *RangeArray::operator[] (int i) const {
    return at(i);
}

Range *RangeArray::at(int i) const {
    if( i > array_used_ - 1 || i < 0){
        return NULL;
    }else {
        return ref_rray_[i];
    }
}

RangeArray &RangeArray::operator=(const RangeArray &r) {
  if (this != &r) {
    // uses copy with byte_val_map instead
    copy_with_val(r);
    // copy(r);
  }
  return *this;
}

void RangeArray::add_range(Range &r) {
  // Binary search
  int low = 0;
  int mid = low;
  int high = array_used_;

  while (low < high) {
    mid = low + (high - low) / 2;
    if(ref_rray_[mid]->get_begin() < r.get_begin() ) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }

  insert_range(low, r);
}

void RangeArray::add_range(unsigned int begin_addr, unsigned int len) {
  // Binary search
  int low = 0;
  int mid = low;
  int high = array_used_;

  while (low < high) {
    mid = low + (high - low) / 2;
    if (ref_rray_[mid]->get_begin() < begin_addr) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }

  insert_range(low, begin_addr, len);
}

void RangeArray::add_range(uint32_t begin_addr,
                           uint32_t len,
                           std::multimap<uint32_t, uint32_t> &byte_val_map) {
  // Binary search
  int low = 0;
  int mid = low;
  int high = array_used_;

  while (low < high) {
    mid = low + (high - low) / 2;
    if (ref_rray_[mid]->get_begin() < begin_addr) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }

  insert_range(low, begin_addr, len, byte_val_map);
}

bool RangeArray::del_range(unsigned int begin_addr, unsigned int len)
{
    // binary search
    int low = 0;
    int high = array_used_;
    int mid = low;
    int end = begin_addr + len;

    bool is_del = false;

    while(low < high){
        mid = low + (high - low) / 2;
        if(ref_rray_[mid]->get_begin() < begin_addr){
            low = mid + 1;
        }else {
            high = mid;
        }
    }

    if(low > 0){
        low--;
    }

    int to_del = 0;
    int first = -1;

    for(int i = low; i < array_used_; i++) {
        unsigned int save_begin;
        unsigned int save_end;

        if(ref_rray_[i]->get_begin() >= end){
            break;
        }

        save_begin = ref_rray_[i]->get_begin();
        save_end = ref_rray_[i]->get_end();

        if(save_begin >= begin_addr &&
                save_end <= end){
            // remove ref_rray_[i]
            if(first == -1){
                first = i;
            }
            to_del++;

            is_del = true;
        } else {
            // save_begin < begin_addr or
            // save_end > end
            if(save_begin < begin_addr){
                if(save_end > end){
                    // range splits into two
                    ref_rray_[i]->set_end(begin_addr);
                    insert_range(i+1, end, save_end - end);

                    is_del = true;
                    break;
                }else if(save_end > begin_addr){
                    // save_end <= end
                    ref_rray_[i]->set_end(begin_addr);
                    is_del = true;
                }
            } else {
                // save_begin >= begin && save_end > end
                ref_rray_[i]->set_begin(end);
                is_del = true;
            }
        }
    }

    if(first != -1){
        remove_ranges(first, first + to_del - 1);
    }

    return is_del;
}

// Displays all current ranges in the range array
void RangeArray::disp_range_array() const
{
    Range *range;
    for(int i = 0; i < array_used_; i++){
        range = ref_rray_[i];
        cout << "begin addr: " << hex << (*range).get_begin()
                << " len: " << dec << (*range).get_len() << " bytes" << endl;
    }
}

void RangeArray::disp_byte_val_map_array() {
  for(int i = 0; i < array_used_; i++){
    cout << "range begin: " << hex << ref_rray_[i]->get_begin() << endl;
    ref_rray_[i]->disp_byte_val_map();
  }
}

bool RangeArray::has_ident_range(unsigned int begin_addr, unsigned int len)
{
    for(int i = 0; i < array_used_; i++){
        if(ref_rray_[i]->get_begin() == begin_addr &&
           ref_rray_[i]->get_end() == begin_addr + len){
            return true;
        }
    }
    return false;
}

bool RangeArray::has_range(unsigned int begin_addr, unsigned int len)
{
    for(int i = 0; i < array_used_; i++){
        if(ref_rray_[i]->get_begin() <= begin_addr &&
                ref_rray_[i]->get_end() >= begin_addr + len){
            return true;
        }
    }
    return false;
}

bool RangeArray::has_range(Range &r)
{
    return has_range(r.get_begin(), r.get_len() );
}

bool RangeArray::is_identical(RangeArray &ra)
{
    if(array_used_ == ra.get_size() ){
        for(int i = 0; i < array_used_; i++){
            if(ref_rray_[i]->get_begin() == ra[i]->get_begin() &&
               ref_rray_[i]->get_end() == ra[i]->get_end() ){
                // continue;
            }else{
                return false;
            }
        }
        return true;
    }else {
        return false;
    }
}

void RangeArray::get_common_range(RangeArray &ra_right, RangeArray &common) {
  int idx_left = 0;
  int idx_right = 0;

  Range *range_left;
  Range *range_right;
  RangeArray &ra_left = *this;

  common.reset();

  // find the common ranges of left range and right range
  while (true) {
    range_left = ra_left[idx_left];
    range_right = ra_right[idx_right];

    if (range_left == NULL || range_right == NULL) {
      break;
    }

    // chooses the larger begin addr
    // chooses the smaller end addr
    // which make it common range between left and right
    unsigned int
        common_begin = max(range_left->get_begin(), range_right->get_begin());
    unsigned int
        common_end = min(range_left->get_end(), range_right->get_end());

    if (common_begin < common_end) {
      // This is the common range
      common.add_range(common_begin, common_end - common_begin);
    }

    // if left range is smaller than right range, increases it
    // notices that all ranges in range array are in increasing order
    if (range_left->get_end() < range_right->get_end()) {
      idx_left++;
    } else if (range_right->get_end() < range_left->get_end()) {
      idx_right++;
    } else {
      idx_left++;
      idx_right++;
    }
  }
}

void RangeArray::get_common_range_with_val(RangeArray &ra_right,
                                           RangeArray &common) {
  int idx_left = 0;
  int idx_right = 0;

  Range *range_left;
  Range *range_right;
  RangeArray &ra_left = *this;

  common.reset();

  // find the common ranges of left range and right range
  while (true) {
    range_left = ra_left[idx_left];
    range_right = ra_right[idx_right];

    if (range_left == NULL || range_right == NULL) {
      break;
    }

    // chooses the larger begin addr
    // chooses the smaller end addr
    // which make it common range between left and right
    unsigned int
        common_begin = max(range_left->get_begin(), range_right->get_begin());
    unsigned int
        common_end = min(range_left->get_end(), range_right->get_end());

    if (common_begin < common_end) {
      // This is the common range
      multimap<uint32_t,uint32_t> byte_val_map = get_byte_val_map(*range_right,
                                                                  common_begin,
                                                                  common_end);
      common.add_range(common_begin, common_end - common_begin, byte_val_map);
    }

    // if left range is smaller than right range, increases it
    // notices that all ranges in range array are in increasing order
    if (range_left->get_end() < range_right->get_end()) {
      idx_left++;
    } else if (range_right->get_end() < range_left->get_end()) {
      idx_right++;
    } else {
      idx_left++;
      idx_right++;
    }
  }

//  for(int i = 0; i < common.get_size(); i++) {
//    common[i]->disp_range();
//    common[i]->disp_byte_val_map();
//  }
}

RangeArray &RangeArray::get_common_range(RangeArray &r)
{
    RangeArray common;
    get_common_range(r, common);

    // Important
    *this = common;
    return *this;
}

RangeArray& RangeArray::get_common_range_with_val(RangeArray &r) {
  RangeArray common;
  get_common_range_with_val(r, common);

  *this = common;
//  cout << "common range array size: " << common.get_size() << endl;
//  cout << "this range array size: " << this->get_size() << endl;
  return *this;
}

unsigned int RangeArray::get_size() const{ return array_used_; }

void RangeArray::copy(const RangeArray &src) {
  // resets old
  reset();

  if (array_size_ < src.get_size()) {
    array_size_ = src.get_size();
    delete[] ref_rray_;
    ref_rray_ = new Range *[array_size_];
  }

  for (int i = 0; i < src.get_size(); i++) {
    Range *old = src[i];
    Range *copy = new Range(old->get_begin(), old->get_len());
    ref_rray_[i] = copy;
    array_used_++;
  }
}

void RangeArray::copy_with_val(const RangeArray &src) {
  reset();

  if (array_size_ < src.get_size()) {
    array_size_ = src.get_size();
    delete[] ref_rray_;
    ref_rray_ = new Range *[array_size_];
  }

  for (int i = 0; i < src.get_size(); i++) {
    Range *old = src[i];
    Range *copy = new Range(old->get_begin(), old->get_len(),
                            old->get_byte_val_map() );
    ref_rray_[i] = copy;
    array_used_++;
  }
}

void RangeArray::init() {
    array_size_ = 8;
    array_used_ = 0;
    ref_rray_ = new Range *[array_size_];
}

void RangeArray::remove_ranges(int first, int last)
{
    if(first > array_used_ - 1 || last > array_used_ - 1){
        return;
    }
    assert(last >= first);

    int i;
    int gap;
    Range *r;

    for(i = first; i <= last; i++){
        r = ref_rray_[i];
        delete r;
    }

    gap = last - first + 1;
    for(i = first; i < array_used_ - gap; i++){
        ref_rray_[i] = ref_rray_[i + gap];
    }

    array_used_ -= gap;
}

void RangeArray::remove_range(int pos)
{
    remove_ranges(pos, pos);
}

void RangeArray::reset()
{
//  cout << "num used array: " << array_used_ << endl;
  for(int i = 0; i < array_used_; i++) {
    ref_rray_[i]->disp_range();
  }

  for (int i = 0; i < array_used_; i++) {
    delete ref_rray_[i];
  }
  array_used_ = 0;
}

multimap<uint32_t, uint32_t> RangeArray::get_byte_val_map(Range &r,
                                                          uint32_t range_begin,
                                                          uint32_t range_len) {
  multimap<uint32_t, uint32_t> byte_val_map;
  if(r.get_begin() > range_begin ||
      r.get_end() < range_len) {
    cout << "err: given range exceeds range of r" << endl;
  } else {
//    const multimap<uint32_t, uint32_t> &temp_map = r.get_byte_val_map();
    for(uint32_t i = range_begin; i < range_len; i++){
      pair<multimap<uint32_t, uint32_t>::const_iterator,
           multimap<uint32_t, uint32_t>::const_iterator > ret;
      ret = r.get_byte_val_map().equal_range(i);
//      ret = temp_map.equal_range(i);

      for(multimap<uint32_t,uint32_t>::const_iterator it = ret.first;
          it != ret.second; ++it) {
        byte_val_map.insert(*it);
      }
    }
  }

//  for(multimap<uint32_t,uint32_t>::iterator it = byte_val_map.begin();
//      it != byte_val_map.end(); ++it) {
//    cout << "addr: " << hex << it->first << " val: " << hex << it->second
//         << endl;
//  }
  return byte_val_map;
}

void RangeArray::insert_range(int pos, Range &r) {
  if (pos > array_used_) {
    cout << "insert_range: pos is larger than used" << endl;
    return;
  }

  Range *range = new Range(r);

  if (array_used_ + 1 > array_size_) {
    // grow size
    array_size_ += array_size_;
    Range **new_array = new Range *[array_size_];
    for (int i = 0; i < pos; i++) {
      new_array[i] = ref_rray_[i];
    }

    new_array[pos] = range;

    for (int i = pos + 1; i < array_used_ + 1; i++) {
      new_array[i] = ref_rray_[i - 1];
    }

    delete[] ref_rray_;
    ref_rray_ = new_array;
  } else {
    for (int i = array_used_ - 1; i >= pos; i--) {
      ref_rray_[i + 1] = ref_rray_[i];
    }
    ref_rray_[pos] = range;
  }
  array_used_++;
}

void RangeArray::insert_range(int pos,
                              unsigned int begin_addr,
                              unsigned int len)
{
  if (pos > array_used_) {
    cout << "insert_range: pos is larger than used" << endl;
    return;
  }

  Range *range = new Range(begin_addr, len);

  if (array_used_ + 1 > array_size_) {
    // grow size
    array_size_ += array_size_;
    Range **new_array = new Range *[array_size_];
    for (int i = 0; i < pos; i++) {
      new_array[i] = ref_rray_[i];
    }

    new_array[pos] = range;

    for (int i = pos + 1; i < array_used_ + 1; i++) {
      new_array[i] = ref_rray_[i - 1];
    }

    delete[] ref_rray_;
    ref_rray_ = new_array;
  } else {
    for (int i = array_used_ - 1; i >= pos; i--) {
      ref_rray_[i + 1] = ref_rray_[i];
    }
    ref_rray_[pos] = range;
  }
  array_used_++;
}


void RangeArray::insert_range(int pos,
                              uint32_t begin_addr,
                              uint32_t len,
                              multimap<uint32_t, uint32_t> &byte_val_map) {
  if (pos > array_used_) {
    cout << "insert_range: pos is larger than used" << endl;
    return;
  }

  Range *range = new Range(begin_addr, len, byte_val_map);

  if (array_used_ + 1 > array_size_) {
    // grow size
    array_size_ += array_size_;
    Range **new_array = new Range *[array_size_];
    for (int i = 0; i < pos; i++) {
      new_array[i] = ref_rray_[i];
    }

    new_array[pos] = range;

    for (int i = pos + 1; i < array_used_ + 1; i++) {
      new_array[i] = ref_rray_[i - 1];
    }

    delete[] ref_rray_;
    ref_rray_ = new_array;
  } else {
    for (int i = array_used_ - 1; i >= pos; i--) {
      ref_rray_[i + 1] = ref_rray_[i];
    }
    ref_rray_[pos] = range;
  }
  array_used_++;
}