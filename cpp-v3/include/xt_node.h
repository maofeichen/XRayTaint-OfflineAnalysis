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
       std::string flag,
       std::string addr,
       std::string val);
  Node& operator=(const Node &rhs);

  bool        is_mark() const;
  bool        is_mem() const { return is_mem_; }
  uint32_t    get_index() const;

  void        set_flag(std::string flag);
  std::string get_flag() const;
  std::string get_addr() const;
  std::string get_val() const;
  void        set_int_addr(uint32_t i_addr);
  uint32_t    get_int_addr() const;
  void        set_sz_bit(uint32_t sz_bit);
  void        set_sz_byte(uint32_t sz_byte);
  uint32_t    get_sz_bit() const ;
  uint32_t    get_sz_byte() const;

  void        set_mem_flag(bool is_mem) { is_mem_ = is_mem; }
  bool        get_mem_flag() const { return is_mem_; }

  void print_mem_node();
  void print_node();

 private:
  bool is_mark_     = false;
  bool is_mem_      = false;
  uint32_t index_   = 0;

  std::string flag_ = "";
  std::string addr_ = "";
  std::string val_  = "";

  uint32_t int_addr_= 0;
  uint32_t sz_bit_  = 0;
};

#endif //XT_NODE_H
