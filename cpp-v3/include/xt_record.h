#ifndef XT_RECORD_H
#define XT_RECORD_H

#include "xt_node.h"
#include <cstdint>

class Record{
 public:
  Record(uint32_t index);

  bool init_record(std::string s_rec);
  bool is_makr();

  void     set_index(uint32_t index);
  uint32_t get_index();
  Node get_src_node();
  Node get_dst_node();

  void print_record();

 private:
  bool is_mark_   = false;
  uint32_t index_ = 0;

  Node src_;
  Node dst_;
};

#endif //XT_RECORD_H
