#include "RangeArray.h"

#include <cassert>
#include <iostream>

using namespace std;

RangeArray::RangeArray() {init(); }

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

RangeArray &RangeArray::operator=(const RangeArray &r)
{
    if(this != &r){
        copy(r);
    }
    return *this;
}

void RangeArray::add_range(unsigned int begin_addr, unsigned int len)
{
    // Binary search
    int low = 0;
    int mid = low;
    int high = array_used_;

    while(low < high){
        mid = low + (high - low) / 2;
        if(ref_rray_[mid]->get_begin() < begin_addr ){
            low = mid + 1;
        } else{
            high = mid;
        }
    }

    insert_range(low, begin_addr, len);
}

// Displays all current ranges in the range array
void RangeArray::disp_range_array()
{
    Range *range;
    for(int i = 0; i < array_used_; i++){
        range = ref_rray_[i];
        cout << "begin addr: " << hex << (*range).get_begin()
                << " len: " << dec << (*range).get_len() << " bytes" << endl;
    }
}

void RangeArray::get_common_range(RangeArray &ra_right, RangeArray &common)
{
    int idx_left = 0;
    int idx_right = 0;

    Range *range_left;
    Range *range_right;
    RangeArray &ra_left = *this;

    common.reset();

    // find the common ranges of left range and right range
    while(true){
        range_left = ra_left[idx_left];
        range_right = ra_right[idx_right];

        if(range_left == NULL || range_right == NULL){
            break;
        }

        // chooses the larger begin addr
        // chooses the smaller end addr
        // which make it common range between left and right
        unsigned int common_begin = max(range_left->get_begin(), range_right->get_begin() );
        unsigned int common_end   = min(range_left->get_end(), range_right->get_end() );

        if(common_begin < common_end){
            // This is the common range
            common.add_range(common_begin, common_end - common_begin);
        }

        // if left range is smaller than right range, increases it
        // notices that all ranges in range array are in increasing order
        if(range_left->get_end() < range_right->get_end() ){
            idx_left++;
        }else if(range_right->get_end() < range_left->get_end() ){
            idx_right++;
        }else {
            idx_left++;
            idx_right++;
        }
    }
}

RangeArray &RangeArray::get_common_range(RangeArray &r)
{
    RangeArray common;
    get_common_range(r, common);

    // Important
    *this = common;
    return *this;
}

unsigned int RangeArray::get_size() const{ return array_used_; }

void RangeArray::copy(const RangeArray &src)
{
    // resets old
    reset();

    if(array_size_ < src.get_size() ){
        array_size_ = src.get_size();
        delete[] ref_rray_;
        ref_rray_ = new Range *[array_size_];
    }

    for(int i = 0; i < src.get_size(); i++){
        Range *old = src[i];
        Range *copy = new Range(old->get_begin(), old->get_len() );
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

void RangeArray::reset() {
    for(int i = 0; i < array_used_; i++) {
        delete ref_rray_[i];
    }
    array_used_ = 0;
}

void RangeArray::insert_range(int pos,
                              unsigned int begin_addr,
                              unsigned int len)
{
    if(pos > array_used_){
        cout << "insert_range: pos is larger than used" << endl;
        return;
    }

    Range *range = new Range(begin_addr, len);

    if(array_used_ + 1 > array_size_){
        // grow size
        array_size_ += array_size_;
        Range **new_array = new Range *[array_size_];
        for(int i = 0; i < pos; i++){
            new_array[i] = ref_rray_[i];
        }

        new_array[pos] = range;

        for(int i = pos + 1; i < array_used_ + 1; i++){
            new_array[i] = ref_rray_[i - 1];
        }

        delete[] ref_rray_;
        ref_rray_ = new_array;
    }else{
        for (int i = array_used_ - 1; i >= pos; i--){
            ref_rray_[i+1] = ref_rray_[i];
        }
        ref_rray_[pos] = range;
    }
    array_used_++;
}
