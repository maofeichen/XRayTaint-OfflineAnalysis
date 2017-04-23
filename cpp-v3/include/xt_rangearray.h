#ifndef XT_RANGEARRAY_H_
#define XT_RANGEARRAY_H_

#include "xt_range.h"
#include <cstdint>
#include <map>

class RangeArray{
public:
  RangeArray() { init(); }
  RangeArray(uint32_t begin, uint32_t len);
  RangeArray(const Range& r);
  ~RangeArray();

  const Range* operator[](uint32_t i) const;
  const Range* at(uint32_t i) const;
  RangeArray& operator=(const RangeArray& rhs);

  void add_range(const Range& r);
  void add_range(uint32_t begin, uint32_t len);
  void add_range(uint32_t begin, uint32_t len,
                 const std::multimap<uint32_t,uint32_t>& byte_val_map);

  uint32_t get_size() const { return array_use_; }

  void print_range_array() const;
private:
  Range **ref_array_;
  uint32_t array_sz_;
  uint32_t array_use_;

  void copy(const RangeArray& rhs);
  void copy_with_val(const RangeArray& rhs);

  void init();
  void reset();

  void insert_range(int pos, const Range& r);
  void insert_range(int pos,
                    uint32_t begin,
                    uint32_t len);
  void insert_range(int pos,
                    uint32_t begin,
                    uint32_t len,
                    const std::multimap<uint32_t,uint32_t>& byte_val_map);
};

#endif /* XT_RANGEARRAY_H_ */
