// This class referenced CipherXray's RangeArray class.

// After byte taint analysis, for each byte of potential
// input buffer, we generates its propagation result,
// which are a series of <byte addr, val>.
// We now merge these single bytes into continuous buffers (ranges)
// for further analysis.

#ifndef RANGEARRAY_H_
#define RANGEARRAY_H_

#include <map>

class Range {
 public:
  Range();
  Range(const Range &r);
  Range(unsigned int begin_addr, unsigned int len) {
    begin_addr_ = begin_addr;
    end_addr_ = begin_addr + len;
  }
  // Init range with 1 byte len
  Range(uint32_t begin_addr, uint32_t len, uint32_t val);
  Range(uint32_t begin_addr, uint32_t len,
        const std::multimap<uint32_t,uint32_t> &byte_val_map);

  void set_begin(unsigned int begin_addr) { begin_addr_ = begin_addr; }
  unsigned int get_begin() const { return begin_addr_; }
  void set_end(unsigned int end_addr) { end_addr_ = end_addr; }
  unsigned int get_end() const { return end_addr_; }
  unsigned int get_len() { return end_addr_ - begin_addr_; }

  void set_byte_val_map(std::multimap<uint32_t,uint32_t> &byte_val_map);
  const std::multimap <uint32_t , uint32_t > &get_byte_val_map() const {
    return byte_val_map_;
  }

  void add_byte_val(uint32_t byte_addr, uint32_t val);
  void disp_byte_val_map();
  void disp_range() const ;
  bool has_range(unsigned int begin_addr, unsigned int len);
  bool is_continuous_range(Range &r);
  bool is_identical_range(Range &r);
  bool is_identical_byte_val_map(const std::multimap<uint32_t,uint32_t> &byte_val_map);

 private:
  unsigned int begin_addr_;
  unsigned int end_addr_; // end addr is 1 byte pass the last byte

  // Uses multimap to store values of each byte in the range.
  // There are might be multi value per byte
  std::multimap <uint32_t, uint32_t> byte_val_map_;
};

class RangeArray {
 public:
  RangeArray();
  RangeArray(Range &r);
  RangeArray(const Range &r);
  RangeArray(unsigned int begin_addr, unsigned int len);
  ~RangeArray();

  Range *operator[](int i) const;
  Range *at(int i) const;
  RangeArray &operator=(const RangeArray &r);

  void add_range(Range &r);
  void add_range(unsigned int begin_addr, unsigned int len);
  void add_range(uint32_t begin_addr, uint32_t len,
                 std::multimap<uint32_t,uint32_t> &byte_val_map);

  // Deletes range in the range array, given the range
  bool del_range(unsigned int begin_addr, unsigned int len);
  void disp_range_array() const ;
  void disp_byte_val_map_array();

  // Result common ranges stores in common
  void get_common_range(RangeArray &ra_right, RangeArray &common);
  void get_common_range_with_val(RangeArray &ra_right, RangeArray &common);
  RangeArray &get_common_range(RangeArray &r);
  RangeArray &get_common_range_with_val(RangeArray &r);

  unsigned int get_size() const;

  bool has_ident_range(unsigned int begin_addr, unsigned int len);
  bool has_range(unsigned int begin_addr, unsigned int len);
  bool has_range(Range &r);

  // Compars if two rangearrays have same ranges
  bool is_identical(RangeArray &ra);

  // Removes ranges given their positions in the range array
  void remove_ranges(int first, int last);
  void remove_range(int pos);
  void reset();

 private:
  Range **ref_rray_;
  unsigned int array_size_;
  unsigned int array_used_;

  void copy(const RangeArray &src);
  void copy_with_val(const RangeArray &src);
  void init();

  std::multimap<uint32_t, uint32_t> get_byte_val_map(Range &r,
                                                     uint32_t range_begin,
                                                     uint32_t range_len);

  void insert_range(int pos, Range &r);
  void insert_range(int pos, unsigned int begin_addr, unsigned int len);
  void insert_range(int pos, uint32_t begin_addr, uint32_t len,
                    std::multimap<uint32_t,uint32_t> &byte_val_map);

};

#endif /* RANGEARRAY_H_ */
