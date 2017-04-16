#ifndef XT_LIVENESS_H_
#define XT_LIVENESS_H_

#include "xt_file.h"
#include "xt_log.h"

class Liveness {
public:
  Liveness() {}
  void analyze_liveness(bool is_dump,
                        const std::string curr_t,
                        const xt_file::File& file,
                        const Log& log);
private:

  bool is_buf_alive(const uint32_t esp, const uint32_t addr);
  bool is_stack_alive(const uint32_t esp, const uint32_t addr);
  bool is_heap_alive();

  void
  analyze_alive_buf(const Log& log,
                    std::vector< std::vector<Record> >& alive_func);
  std::vector<Record>
  analyze_alive_buf_per_func(const std::vector<Record>& pair_func);

  void
  merge_continuous_buf(std::vector< std::vector<Record> >& alive_func);
};



#endif /* XT_LIVENESS_H_ */
