#ifndef XT_RECORD_H
#define XT_RECORD_H

#include "xt_flag.h"
#include "xt_node.h"
#include <cstdint>

class Record{
 public:
  Record(uint32_t index);
  Record(const Record &rhs);

  Record& operator=(const Record &rhs);

  bool init_record(const std::string &s_rec);
  bool is_makr() const;
  bool is_mem_type(const flag::Mem_Type mt);

  void     set_index(uint32_t index);
  uint32_t get_index() const;
  Node &get_src_node();
  Node &get_dst_node();
  const Node &get_const_src_node() const { return src_; }
  const Node &get_const_dst_node() const { return dst_; }

  void           set_mem_type(flag::Mem_Type mt) { mt_ = mt; };
  flag::Mem_Type get_mem_type() const { return mt_; }

  void print_record() const;

 private:
  bool is_mark_      = false;
  uint32_t index_    = 0;
  flag::Mem_Type mt_ = flag::M_UNKNOW;

  Node src_;
  Node dst_;
};

#endif //XT_RECORD_H
