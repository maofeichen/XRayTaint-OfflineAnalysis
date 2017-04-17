#ifndef XT_LIVENESS_H_
#define XT_LIVENESS_H_

#include "xt_data.h"
#include "xt_file.h"
#include "xt_log.h"

class Liveness {
public:
  Liveness() {}
  void analyze_liveness(bool is_dump,
                        const std::string curr_t,
                        const xt_file::File& file,
                        const Log& log,
                        std::vector<Alive_Func_>& v_liveness_res);
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
                       std::vector<Alive_Func_>& v_liveness_res);
  void
  merge_continuous_buf_per_func(Alive_Func_& alive_func_res,
                                const std::vector<Record>& alive_func);
  void
  analyze_alive_node(Alive_Func_& alive_func_res,
                     std::vector<Node>& alive_node);
  void
  create_continuous_buf(Alive_Func_& alive_func_res,
                        const std::vector<Node>& alive_node);

  // filters out buffers that size is < 8 bytes
  void filter_invalid_cont_buf(std::vector<Alive_Func_>& v_liveness_res);
  void filter_kernel_buf(std::vector<Alive_Func_>& v_liveness_res);

  void print_liveness(std::vector<Alive_Func_>& v_liveness_res);
  void print_func(const Alive_Func_& alive_func_res);
  void print_func_mark(const Alive_Func_& alive_func_res);
  void print_cont_buf(const Cont_Buf_& cont_buf);
};

#endif /* XT_LIVENESS_H_ */
