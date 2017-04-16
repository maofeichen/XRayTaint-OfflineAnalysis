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
  struct Cont_Buf_{
    uint32_t begin_addr = 0;
    uint32_t byte_sz    = 0;
    std::vector<uint32_t> v_node_idx;

//    Cont_Buf_() {}
//    Cont_Buf_(const Cont_Buf_& rhs) {
//      begin_addr = rhs.begin_addr;
//      byte_sz    = rhs.byte_sz;
//      v_node_idx = rhs.v_node_idx;
//    }
  };

  struct Alive_Func_{
    Node fir_c_mark;
    Node sec_c_mark;
    Node fir_r_mark;
    Node sec_r_mark;
    std::vector<Cont_Buf_> v_cont_buf;

    Alive_Func_() {}
    Alive_Func_(const Alive_Func_& rhs) {
      fir_c_mark = rhs.fir_c_mark;
      sec_c_mark = rhs.sec_c_mark;
      fir_r_mark = rhs.fir_r_mark;
      sec_r_mark = rhs.sec_r_mark;
      for(auto it = rhs.v_cont_buf.begin(); it != rhs.v_cont_buf.end(); ++it) {
        v_cont_buf.push_back(*it);
      }
    }
  };

  std::vector<Alive_Func_> v_liveness_res_;

  bool is_buf_alive(const uint32_t esp, const uint32_t addr);
  bool is_stack_alive(const uint32_t esp, const uint32_t addr);
  bool is_heap_alive();

  void
  analyze_alive_buf(const Log& log,
                    std::vector< std::vector<Record> >& alive_func);
  std::vector<Record>
  analyze_alive_buf_per_func(const std::vector<Record>& pair_func);

  void
  merge_continuous_buf(const std::vector< std::vector<Record> >& all_alive_func);
  void
  merge_continuous_buf_per_func(Alive_Func_& alive_func_res,
                                const std::vector<Record>& alive_func);
  void
  analyze_alive_node(Alive_Func_& alive_func_res,
                     std::vector<Node>& alive_node);
  void
  create_continuous_buf(Alive_Func_& alive_func_res,
                        const std::vector<Node>& alive_node);

  void print_liveness();
  void print_liveness_func(const Alive_Func_& alive_func_res);
  void print_cont_buf(const Cont_Buf_& cont_buf);
};



#endif /* XT_LIVENESS_H_ */
