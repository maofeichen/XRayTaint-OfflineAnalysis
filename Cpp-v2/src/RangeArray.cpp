#include "RangeArray.h"

#include <iostream>

using namespace std;

RangeArray::RangeArray() {init(); }

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

unsigned int RangeArray::get_size() const{ return array_used_; }

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
