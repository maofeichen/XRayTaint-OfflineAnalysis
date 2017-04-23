#ifndef XT_AVALANCHE_H_
#define XT_AVALANCHE_H_

#include "xt_alivefunc.h"
#include "xt_log.h"
#include "xt_propagate.h"
#include "xt_rangearray.h"
#include "xt_taintpropagate.h"

#include <vector>
#include <unordered_set>

class Avalanche{
public:
  Avalanche(const Log& log, Propagate& prpgt) : log_(log), prpgt_(prpgt) {}
  void detect(const std::vector<AliveFunction>& v_liveness);

private:
  const Log& log_;
  Propagate& prpgt_;

  struct Taint_Src_ {
    uint32_t node_idx;
    uint8_t  pos; // Indicates which byte is the taint source
  };

  struct Multi_Taint_Src_ {
    uint32_t addr = 0;
    std::vector<Taint_Src_> v_taint_src;
  };

  struct Prpgt_Byte_ {
    uint32_t addr   = 0;
    std::string val = "0";

    bool operator<(const Prpgt_Byte_& rhs) const {
      return addr < rhs.addr;
    }

    void print_prpgt_byte() {
      std::cout << "addr: " << std::hex << addr << " val: " << val << std::endl;
    }
  };

  void detect_in_out(const ContinueBuf& in,
                     const ContinueBuf& out);
  void gen_in_byte_prpgt(const ContinueBuf& in,
                         std::vector<std::vector<Prpgt_Byte_> >& in_prpgt_res);
  // There might be multiple sources for a byte, so group multi sources if
  // any, for further propagation search
  void gen_in_taint_src(const ContinueBuf& in,
                        std::vector<Multi_Taint_Src_>& in_taint_src);
  // Generates range arrays for all bytes of input buffer as taint sources
  void gen_in_taint_ra(const ContinueBuf& in,
                       const std::vector<std::vector<Prpgt_Byte_> >& in_prpgt_res,
                       std::vector<TaintPropagate *>& in_prpgt_ra_res);
  void gen_in_taint_ra_per_byte(const std::vector<Prpgt_Byte_>& byte_prpgt_res,
                                RangeArray *byte_taint_prpgt);

  void merge_prpgt_res(std::unordered_set<Node,NodeHash> &prpgt_res,
                       std::unordered_set<Node,NodeHash> &set_prpgt_res);
  void to_prpgt_byte(std::unordered_set<Node,NodeHash> &set_propagate_res,
                     std::vector<Prpgt_Byte_>& v_prpgt_byte);

  Node get_mem_node(uint32_t idx);
  uint8_t compute_byte_pos(const uint32_t addr, const Node& node);
};

#endif /* XT_AVALANCHE_H_ */
