#ifndef XT_LOG_H
#define XT_LOG_H

#include <cstdint>
#include <string>
#include <vector>
#include "xt_record.h"

class Log{
 public:
  Log(std::vector<std::string> &v_s_log);

  Record get_record(uint32_t index);
  uint32_t find_record(std::string s_rec);
  uint32_t get_size();

  void print_log();
 private:
  std::vector<Record> v_rec_;

  void init_log(std::vector<std::string> &v_s_log);
};

#endif //XT_LOG_H
