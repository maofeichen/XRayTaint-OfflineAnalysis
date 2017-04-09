// This class is used to detect blocks, modes after liveness
// analysis.

#ifndef XT_DETECT_H_
#define XT_DETECT_H_

#include "xt_ByteTaintPropagate.h"
#include "xt_propagate.h"
#include "xt_log.h"
#include "RangeArray.h"

#include <unordered_set>
#include <vector>

class Detect {
 public:
  Detect(std::vector<t_AliveFunctionCall> v_func_cont_buf,
         XTLog &xt_log,
         std::vector<Record> log_rec);

  void detect_cipher();
 private:
  XTLog xt_log_;
  std::vector<t_AliveFunctionCall> v_func_cont_buf_;
  std::vector<Record> log_rec_;

  struct propagate_byte_ {
    unsigned long addr = 0;
    std::string val = "0";

    bool operator<(const propagate_byte_ &propagate_byte) const {
      return (addr < propagate_byte.addr);
    }
  };

  struct pair_inout_ {
    t_AliveContinueBuffer in_;
    t_AliveContinueBuffer out_;
  };

  struct Taint_Source_ {
    uint32_t node_idx;
    u_int8_t pos; // Indicates which byte is the taint source
  };

  struct Multi_Taint_Source_ {
    uint32_t addr = 0;
    std::vector<Detect::Taint_Source_> v_multi_src;
  };

  // Due to there might be multiple same taint sources (same addr, different val),
  // computes the interval to next different taint source
  inline unsigned long comp_multi_src_interval(std::vector<unsigned long> &v_node_idx,
                                               std::vector<unsigned long>::const_iterator it_node_idx);

  inline std::string get_insn_addr(unsigned long idx,
                                   std::vector<Record> &v_rec);
  inline void merge_propagate_res(std::unordered_set<Node,
                                                     NodeHash> &propagate_res,
                                  std::unordered_set<Node,
                                                     NodeHash> &multi_propagate_res);
  inline bool is_dupl_buf_inout(Detect::pair_inout_ &bufInOut,
                                std::vector<Detect::pair_inout_> &vBufInOut);

  // Computes propagate results for multiple sources
  std::unordered_set<Node, NodeHash> comp_multi_src_propagate_res(
      unsigned int multi_src_interval,
      std::vector<unsigned long>::const_iterator it_multi_src_idx,
      unsigned int byte_pos,
      Propagate &propagate);

  // Converts multiple source result set to vector of propagate_byte_
  // for further analysis
  std::vector<Detect::propagate_byte_>
  convert_propagate_byte(std::unordered_set<Node,
                                            NodeHash> &multi_propagate_res);

  // get the memory node (load or store) given the index in the log
  XTNode get_mem_node(unsigned long index);

  // !not used
  // Generates propagate bytes for all bytes of in buffer
  std::vector<std::vector<Detect::propagate_byte_> >
  gen_in_propagate_byte(t_AliveContinueBuffer &in, Propagate &propagate);

  std::vector<std::vector<Detect::propagate_byte_> >
  gen_in_prpgt_byte(t_AliveContinueBuffer &in, Propagate &propagate);

  // Generates range array for 1 byte taint source
  void gen_range_array_per_byte(std::vector<Detect::propagate_byte_> v_propagate_byte,
                                RangeArray *range_array);
  void gen_range_array_per_byte_with_val(std::vector<Detect::propagate_byte_> v_propagate_byte,
                                         RangeArray *range_array);
  // Generate range array for all bytes of in buffer as taint sources
  void gen_in_range_array(t_AliveContinueBuffer &in,
                          std::vector<std::vector<Detect::propagate_byte_> > &in_vec_propagate_byte,
                          std::vector<ByteTaintPropagate *> &in_taint_propagate);
  // There might be multiple sources for a byte, so group multi sources if
  // any, for further propagation search
  std::vector<Detect::Multi_Taint_Source_> gen_taint_source(const t_AliveContinueBuffer &in);


  // Given a node in log, convert it to NodePropagate format as taint source
  // for taint propagation search
  NodePropagate init_taint_source(XTNode &node, std::vector<Record> &log_rec);

  uint8_t compute_byte_pos(uint32_t addr, XTNode &node);

  // Detects cipher between a potential input and output buffers
  bool detect_cipher_in_out(t_AliveContinueBuffer &in,
                            t_AliveContinueBuffer &out,
                            Propagate &propagate);
};

#endif /* XT_DETECT_H_ */
