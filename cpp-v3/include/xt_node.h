#ifndef XT_NODE_H
#define XT_NODE_H

#include <cstdint>
#include <string>

class Node{
 public:
  Node();
  Node(const Node &rhs);
  Node(uint32_t index,
       bool is_mark,
       bool is_mem,
       bool is_src,
       std::string flag,
       std::string addr,
       std::string val);
  Node& operator=(const Node &rhs);
  bool  operator<(const Node& rhs);
  bool  operator==(const Node& rhs) const;

  bool        is_mark() const;
  bool        is_mem() const { return is_mem_; }
  bool        is_src() const { return is_src_; }
  uint32_t    get_index() const;

  void        set_flag(std::string flag);
  std::string get_flag() const;

  void        set_addr(const std::string addr) { addr_ = addr; }
  std::string get_addr() const;

  void        set_val(const std::string val) { val_ = val; }
  std::string get_val() const;

  void        set_int_addr(uint32_t i_addr);
  uint32_t    get_int_addr() const;
  void        set_sz_bit(uint32_t sz_bit);
  void        set_sz_byte(uint32_t sz_byte);
  uint32_t    get_sz_bit() const ;
  uint32_t    get_sz_byte() const;

  void        set_mem_flag(bool is_mem) { is_mem_ = is_mem; }
  bool        get_mem_flag() const { return is_mem_; }

  void print_mem_node() const;
  void print_node() const;

 private:
  bool is_mark_     = false;
  bool is_mem_      = false;
  bool is_src_      = false;
  uint32_t index_   = 0;

  std::string flag_ = "";
  std::string addr_ = "";
  std::string val_  = "";

  uint32_t int_addr_= 0;
  uint32_t sz_bit_  = 0;
};

struct NodeHash{
  std::size_t operator()(const Node& rhs) const {
    uint32_t idx = rhs.get_index();
    if(rhs.is_src() ) { idx = idx * 2; }
    else { idx = idx * 2 + 1;}
    std::size_t h (std::hash<uint32_t>()(idx) );
    return h;
   }
};

#endif //XT_NODE_H
