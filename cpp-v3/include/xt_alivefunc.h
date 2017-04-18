#ifndef XT_ALIVEFUNC_H_
#define XT_ALIVEFUNC_H_

#include "xt_contbuf.h"
#include "xt_node.h"

class AliveFunction{
public:
  AliveFunction() {}
  AliveFunction(const AliveFunction &rhs);

  AliveFunction& operator=(const AliveFunction &rhs);

  void set_fir_c_mark(const Node& fir_c) { fir_c_mark_ = fir_c; }
  const Node& get_fir_c_mark() const { return fir_c_mark_; }

  void set_sec_c_mark(const Node& sec_c) { sec_c_mark_ = sec_c; }
  const Node& get_sec_c_mark() const { return sec_c_mark_; }

  void set_fir_r_mark(const Node& fir_r) { fir_r_mark_ = fir_r; }
  const Node& get_fir_r_mark() const { return fir_r_mark_; }

  void set_sec_r_mark(const Node& sec_r) { sec_r_mark_ = sec_r; }
  const Node& get_sec_r_mark() const { return sec_r_mark_; }

  void set_cont_buf(const std::vector<ContinueBuf> v_continuebuf);
  const std::vector<ContinueBuf>& get_cont_buf() const { return v_continuebuf_; }

  void add_cont_buf(const ContinueBuf& continuebuf);
  void rm_cont_buf_less(const uint32_t byte_sz);
  void rm_cont_buf_large_addr(const uint32_t addr);

  void print_alive_func() const;
private:
  Node fir_c_mark_;
  Node sec_c_mark_;
  Node fir_r_mark_;
  Node sec_r_mark_;
  std::vector<ContinueBuf> v_continuebuf_;
};


#endif /* XT_ALIVEFUNC_H_ */
