#include "xt_range.h"
#include <iostream>

using namespace std;

Range::Range(uint32_t begin, uint32_t len)
{
  begin_ = begin;
  end_   = begin + len;
}

Range::Range(uint32_t begin, uint32_t len,
             const std::multimap<uint32_t,uint32_t> &byte_val_map)
{
  begin_ = begin;
  end_   = begin + len;

  for(auto it = byte_val_map.begin(); it != byte_val_map.end(); ++it) {
    byte_val_map_.insert(*it);
  }
}

Range::Range(const Range& rhs)
{
  begin_ = rhs.begin_;
  end_   = rhs.end_;
  for(auto it = rhs.get_byte_val_map().begin();
      it != rhs.get_byte_val_map().end(); ++it) {
    byte_val_map_.insert(*it);
  }
}

Range&
Range::operator=(const Range& rhs)
{
  begin_ = rhs.begin_;
  end_   = rhs.end_;
  for(auto it = rhs.get_byte_val_map().begin();
      it != rhs.get_byte_val_map().end(); ++it) {
    byte_val_map_.insert(*it);
  }
  return *this;
}

void
Range::set_byte_val_map(const std::multimap<uint32_t,uint32_t> &byte_val_map)
{
  for(auto it = byte_val_map.begin(); it != byte_val_map.end(); ++it) {
    byte_val_map_.insert(*it);
  }
}

void
Range::print_range() const
{
  cout << "begin: " << hex << begin_
       << " len: "  << dec << end_ - begin_ << endl;
}

void
Range::print_byte_val_map() const
{
  for(auto it = byte_val_map_.begin(); it != byte_val_map_.end(); ++it) {
    cout << "addr: " << hex << it->first
         << " val: " << hex << it->second << endl;
  }
}
