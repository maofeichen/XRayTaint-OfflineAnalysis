#ifndef XT_RANGE_H_
#define XT_RANGE_H_
// References Cipherxray's RangeArray class

#include <map>

class Range{
public:
  Range() { begin_ = 0; end_ = 0; };
  Range(uint32_t begin, uint32_t len);
  Range(uint32_t begin, uint32_t len,
        const std::multimap<uint32_t,uint32_t> &byte_val_map);
  Range(const Range& rhs);

  Range& operator=(const Range& rhs);

  void     set_begin(uint32_t begin) { begin_ = begin; }
  uint32_t get_begin() const { return begin_; }

  void     set_end(uint32_t end) { end_ = end; }
  uint32_t get_end() const { return end_; }

  uint32_t get_len() const { return end_ - begin_; }

  void     set_byte_val_map(const std::multimap<uint32_t,uint32_t> &byte_val_map);
  const std::multimap<uint32_t,uint32_t>&
           get_byte_val_map() const { return byte_val_map_; }

  void     print_range() const;
  void     print_byte_val_map() const;
private:
  uint32_t begin_;
  uint32_t end_;  // 1 byte crosses last byte

  // stores <byte, val>. There might be multiple value per byte
  std::multimap<uint32_t, uint32_t> byte_val_map_;

};

#endif /* XT_RANGE_H_ */
