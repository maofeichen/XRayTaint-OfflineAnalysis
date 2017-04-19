#ifndef XT_AVALANCHE_H_
#define XT_AVALANCHE_H_

#include "xt_alivefunc.h"
#include "xt_log.h"
#include <vector>

class Avalanche{
public:
  Avalanche(const Log& log) : log_(log) {}
  void detect(const std::vector<AliveFunction>& v_liveness);

private:
  const Log& log_;

  struct Taint_Src_ {
    uint32_t node_idx;
    uint8_t  pos; // Indicates which byte is the taint source
  };

  struct Multi_Taint_Src_ {
    uint32_t addr = 0;
    std::vector<Taint_Src_> v_taint_src;
  };

  void detect_in_out(const ContinueBuf& in,
                     const ContinueBuf& out);
  void gen_in_byte_prpgt(const ContinueBuf& in);
  // There might be multiple sources for a byte, so group multi sources if
  // any, for further propagation search
  void gen_in_taint_src(const ContinueBuf& in,
                        std::vector<Multi_Taint_Src_>& in_taint_src);
  Node get_mem_node(uint32_t idx);
  uint8_t compute_byte_pos(const uint32_t addr, const Node& node);
};

#endif /* XT_AVALANCHE_H_ */
