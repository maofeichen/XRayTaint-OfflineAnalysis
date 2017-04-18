#ifndef XT_LIVENESS_H_
#define XT_LIVENESS_H_

#include "xt_alivefunc.h"
#include "xt_log.h"

class Liveness {
public:
  Liveness() {}
  void analyze_liveness(const Log& log,
                        std::vector< std::vector<Record> >& r_alive_func,
                        std::vector<AliveFunction>& v_liveness);
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
  merge_continuous_buf(const std::vector< std::vector<Record> >& all_alive_func,
                       std::vector<AliveFunction>& v_liveness);
  void
  merge_continuous_buf_per_func(AliveFunction& alive_func_res,
                                const std::vector<Record>& alive_func);
  void
  analyze_alive_node(AliveFunction& alive_func_res,
                     std::vector<Node>& alive_node);
  void
  create_continuous_buf(AliveFunction& alive_func_res,
                        const std::vector<Node>& alive_node);

  // filters out buffers that size is < 8 bytes
  void filter_invalid_cont_buf(std::vector<AliveFunction>& v_liveness);
  void filter_kernel_buf(std::vector<AliveFunction>& v_liveness_res);
};

#endif /* XT_LIVENESS_H_ */
