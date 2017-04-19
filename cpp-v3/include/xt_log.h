#ifndef XT_LOG_H
#define XT_LOG_H

#include <cstdint>
#include <string>
#include <vector>

#include "xt_flag.h"
#include "xt_record.h"

class Log{
 public:
  Log(const std::vector<std::string> &v_s_log);

  // If a mem rec (load/store), analyze its addr, sz, reset flag
  void analyze_mem_record();
  const Record get_record(uint32_t index) const { return v_rec_[index]; };
  const std::vector<Record>& get_log() const { return v_rec_; }
  uint32_t find_record(std::string s_rec);
  uint32_t get_size() const { return v_rec_.size(); };

  void print_log();
 private:
  std::vector<Record> v_rec_;

  inline uint8_t decode_byte_sz(uint8_t sz_encode);
  inline flag::Mem_Type get_mem_type(const uint32_t flag);
  inline bool is_in_mem_range(const uint32_t flag);
  inline void update_mem_node(Node node,
                              std::string flag_update,
                              uint8_t sz_byte);

  void analyze_mem_record(const uint32_t flag,
                          std::vector<Record>::iterator it_rec);
  void update_store_ptr(std::vector<Record>::iterator it_rec, uint32_t flag);
  void update_store(std::vector<Record>::iterator it_rec, uint32_t flag);
  void update_load_ptr(std::vector<Record>::iterator it_rec, uint32_t flag);
  void update_load(std::vector<Record>::iterator it_rec, uint32_t flag);

  void init_log(const std::vector<std::string> &v_s_log);
};

#endif //XT_LOG_H
