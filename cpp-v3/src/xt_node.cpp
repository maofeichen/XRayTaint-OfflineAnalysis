#include "xt_node.h"
#include <iostream>
using namespace std;

Node::Node() {}

Node::Node(uint32_t index,
           bool is_mark,
           std::string flag,
           std::string addr,
           std::string val) {
  index_   = index;
  is_mark_ = is_mark;
  flag_    = flag;
  addr_    = addr;
  val_     = val;
}

bool Node::is_mark() { return  is_mark_; }

uint32_t Node::get_index() { return index_; }

void Node::set_flag(std::string flag) { flag_ = flag; }

std::string Node::get_flag() { return  flag_; }

std::string Node::get_addr() { return addr_; }

std::string Node::get_val() { return  val_; }

void Node::set_int_addr(uint32_t i_addr) { int_addr_ = i_addr; }

uint32_t Node::get_int_addr() { return int_addr_; }

void Node::set_sz_bit(uint32_t sz_bit) { sz_bit_ = sz_bit; }

uint32_t Node::get_sz_bit() { return sz_bit_; }

uint32_t Node::get_sz_byte() { return  sz_bit_ / 8; }

void Node::print_mem_node() {
  cout << "index: " << dec << index_ << " flag: " << flag_ << " addr in str: "
       << addr_ << " addr in hex: " << hex << int_addr_ << " val: " << val_
       << " size in byte: " << get_sz_byte() << endl;
}

void Node::print_node() {
  cout << "index: " << index_ << " is mark: " << is_mark_ << " flag: " <<
       flag_ << " addr: " << addr_ << " val: " << val_ << endl;
}