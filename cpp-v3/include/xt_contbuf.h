#ifndef XT_CONTBUF_H_
#define XT_CONTBUF_H_

#include <stdint.h>
#include <vector>

class ContinueBuf{
public:
  ContinueBuf() {}
  ContinueBuf(const ContinueBuf &rhs);

  ContinueBuf& operator=(const ContinueBuf &rhs);

  void     set_begin(uint32_t begin_addr) { begin_addr_ = begin_addr; }
  uint32_t get_begin() const { return begin_addr_; }
  void     set_byte_sz(uint32_t byte_sz) { byte_sz_ = byte_sz; }
  uint32_t get_byte_sz() const { return byte_sz_; }

  void     add_node_idx(const uint32_t node_idx);
  void     set_node_idx(const std::vector<uint32_t> &v_node_idx);
  const std::vector<uint32_t>& get_node_idx() const { return v_node_idx_; }

  void     clear_node_idx();
  void     print_cont_buf() const;
  void     print_cont_buf_noidx() const;
private:
  uint32_t begin_addr_ = 0;
  uint32_t byte_sz_    = 0;
  std::vector<uint32_t> v_node_idx_;
};

#endif /* XT_CONTBUF_H_ */
