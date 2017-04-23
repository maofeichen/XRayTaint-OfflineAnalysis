#include "xt_rangearray.h"
#include <stdexcept>
#include <iostream>

using namespace std;

RangeArray::RangeArray(uint32_t begin, uint32_t len)
{
  init();
  add_range(begin, len);
}

RangeArray::RangeArray(const Range& r)
{
  init();
  add_range(r);
}

RangeArray::~RangeArray()
{
  reset();
  delete[] ref_array_;
}

const Range*
RangeArray::operator[](uint32_t i) const
{
  return at(i);
}

const Range*
RangeArray::at(uint32_t i) const
{
  if(i > array_use_-1) { return NULL; }
  else { return ref_array_[i]; }
}


RangeArray&
RangeArray::operator=(const RangeArray& rhs)
{
  if(this != &rhs) {
    copy_with_val(rhs);
  }
  return *this;
}

void
RangeArray::add_range(const Range& r)
{
  // binary searches
  int low    = 0;
  int mid    = low;
  int hi     = array_use_;

  while(low < hi) {
    mid = low + (hi-low) / 2;
    if(ref_array_[mid]->get_begin() < r.get_begin() ) {
      low = mid + 1;
    }else {
      hi  = mid;
    }
  }

  insert_range(low, r);
}

void
RangeArray::add_range(uint32_t begin, uint32_t len)
{
  // binary searches
  int low    = 0;
  int mid    = low;
  int hi     = array_use_;

  while(low < hi) {
    mid = low + (hi-low) / 2;
    if(ref_array_[mid]->get_begin() < begin) {
      low = mid + 1;
    }else {
      hi  = mid;
    }
  }

  insert_range(low, begin, len);
}

void
RangeArray::add_range(uint32_t begin, uint32_t len,
                      const std::multimap<uint32_t,uint32_t>& byte_val_map)
{
  // binary searches
  int low    = 0;
  int mid    = low;
  int hi     = array_use_;

  while(low < hi) {
    mid = low + (hi-low) / 2;
    if(ref_array_[mid]->get_begin() < begin) {
      low = mid + 1;
    }else {
      hi  = mid;
    }
  }

  insert_range(low, begin, len, byte_val_map);
}

void
RangeArray::print_range_array() const
{
  for(uint32_t i = 0; i < array_use_; i++) {
    ref_array_[i]->print_range();
  }
}


void
RangeArray::copy_with_val(const RangeArray& rhs)
{
  reset();

  if(array_sz_ < rhs.get_size() ) {
    array_sz_   = rhs.get_size();
    delete[]    ref_array_;
    ref_array_  = new Range* [array_sz_];
  }

  for(uint32_t i = 0; i < rhs.get_size(); i++) {
    const Range* old  = rhs[i];
    Range* copy       = new Range(old->get_begin(), old->get_len(),
                                  old->get_byte_val_map() );

    ref_array_[i] = copy;
    array_use_++;
  }
}


void
RangeArray::init()
{
  array_sz_   = 8;
  array_use_  = 0;
  ref_array_  = new Range* [array_sz_];
}

void RangeArray::reset()
{
  for(uint32_t i = 0; i < array_use_; i++) {
    delete ref_array_[i];
  }
  array_use_ = 0;
}


void
RangeArray::insert_range(int pos, const Range& r)
{
  if(pos > array_use_) {
    throw runtime_error("insert range: pos is larger than used.");
  }

  Range* range = new Range(r);

  if(array_use_+1 > array_sz_) {
    // grows size
    array_sz_ += array_sz_;
    Range** new_array = new Range* [array_sz_];

    for(int i = 0; i < pos; i++) {
      new_array[i] = ref_array_[i];
    }

    new_array[pos] = range;

    for(int i = pos+1; i < array_use_ + 1; i++) {
      new_array[i] = ref_array_[i-1];
    }

    delete[] ref_array_;
    ref_array_ = new_array;
  }else {
    for(int i = array_use_-1; i >= pos; i--) {
      ref_array_[i+1] = ref_array_[i];
    }
    ref_array_[pos] = range;
  }

  array_use_++;
}

void
RangeArray::insert_range(int pos,
                         uint32_t begin,
                         uint32_t len)
{
  if(pos > array_use_) {
    throw runtime_error("insert range: pos is larger than used.");
  }

  Range* range = new Range(begin, len);

  if(array_use_+1 > array_sz_) {
    // grows size
    array_sz_ += array_sz_;
    Range** new_array = new Range* [array_sz_];

    for(int i = 0; i < pos; i++) {
      new_array[i] = ref_array_[i];
    }

    new_array[pos] = range;

    for(int i = pos+1; i < array_use_ + 1; i++) {
      new_array[i] = ref_array_[i-1];
    }

    delete[] ref_array_;
    ref_array_ = new_array;
  }else {
    for(int i = array_use_-1; i >= pos; i--) {
      ref_array_[i+1] = ref_array_[i];
    }
    ref_array_[pos] = range;
  }

  array_use_++;
}

void
RangeArray::insert_range(int pos,
                         uint32_t begin,
                         uint32_t len,
                         const multimap<uint32_t,uint32_t> &byte_val_map)
{
  if(pos > array_use_) {
    throw runtime_error("insert range: pos is larger than used.");
  }

  Range* range = new Range(begin, len, byte_val_map);

  if(array_use_+1 > array_sz_) {
    // grows size
    array_sz_ += array_sz_;
    Range** new_array = new Range* [array_sz_];

    for(int i = 0; i < pos; i++) {
      new_array[i] = ref_array_[i];
    }

    new_array[pos] = range;

    for(int i = pos+1; i < array_use_ + 1; i++) {
      new_array[i] = ref_array_[i-1];
    }

    delete[] ref_array_;
    ref_array_ = new_array;
  }else {
    for(int i = array_use_-1; i >= pos; i--) {
      ref_array_[i+1] = ref_array_[i];
    }
    ref_array_[pos] = range;
  }

  array_use_++;
}

