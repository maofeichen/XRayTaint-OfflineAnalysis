#include "xt_node.h"
#include <iostream>
using namespace std;

Node::Node() {}

Node::Node(const Node &rhs) {
  index_    = rhs.get_index();
  is_mark_  = rhs.is_mark();
  is_mem_   = rhs.is_mem();
  is_src_   = rhs.is_src();
  flag_     = rhs.get_flag();
  addr_     = rhs.get_addr();
  val_      = rhs.get_val();
  int_addr_ = rhs.get_int_addr();
  sz_bit_   = rhs.get_sz_bit();
}

Node::Node(uint32_t index,
           bool is_mark,
           bool is_mem,
           bool is_src,
           std::string flag,
           std::string addr,
           std::string val) {
  index_   = index;
  is_mark_ = is_mark;
  is_mem_  = is_mem;
  is_src_  = is_src;
  flag_    = flag;
  addr_    = addr;
  val_     = val;
}

Node&
Node::operator=(const Node &rhs) {
  index_    = rhs.get_index();
  is_mark_  = rhs.is_mark();
  is_mem_   = rhs.is_mem();
  is_src_   = rhs.is_src();
  flag_     = rhs.get_flag();
  addr_     = rhs.get_addr();
  val_      = rhs.get_val();
  int_addr_ = rhs.get_int_addr();
  sz_bit_   = rhs.get_sz_bit();

  return *this;
}

bool
Node::operator<(const Node& rhs)
{
  return int_addr_ < rhs.get_int_addr();
}

bool
Node::operator==(const Node& rhs) const
{
  if(flag_ == rhs.get_flag()
     && addr_ == rhs.get_addr()
     && val_  == rhs.get_val() ) {
    return true;
  } else {
    return false;
  }
}

bool Node::is_mark() const { return  is_mark_; }

uint32_t Node::get_index() const { return index_; }

void Node::set_flag(std::string flag) { flag_ = flag; }

std::string Node::get_flag() const { return  flag_; }

std::string Node::get_addr() const { return addr_; }

std::string Node::get_val() const { return  val_; }

void Node::set_int_addr(uint32_t i_addr) { int_addr_ = i_addr; }

uint32_t Node::get_int_addr() const { return int_addr_; }

void Node::set_sz_bit(uint32_t sz_bit) { sz_bit_ = sz_bit; }

void Node::set_sz_byte(uint32_t sz_byte) { sz_bit_ = sz_byte * 8; }

uint32_t Node::get_sz_bit() const { return sz_bit_; }

uint32_t Node::get_sz_byte() const { return  sz_bit_ / 8; }

void Node::print_mem_node() const {
  cout << "index: " << dec << index_ << " flag: " << flag_ << " addr in str: "
       << addr_ << " addr in hex: " << hex << int_addr_ << " val: " << val_
       << " size in byte: " << get_sz_byte() << endl;
}

void Node::print_node() const {
  cout << "index: " << dec << index_ << " is mark: " << is_mark_ << " flag: "
      << flag_ << " addr: " << addr_ << " val: " << val_ << endl;
}
