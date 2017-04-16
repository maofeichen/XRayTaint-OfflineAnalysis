#ifndef XT_LIVENESS_H_
#define XT_LIVENESS_H_

#include "xt_log.h"

class Liveness {
public:
  Liveness() {}
  void analyze_liveness(const Log& log);
private:
  bool is_buf_alive(const uint32_t esp, const uint32_t addr);
  bool is_stack_alive(const uint32_t esp, const uint32_t addr);
  bool is_heap_alive();

  std::vector<Record> analyze_liveness_per_func(const std::vector<Record>& pair_func);
};



#endif /* XT_LIVENESS_H_ */
