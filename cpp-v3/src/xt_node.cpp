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

void Node::print_node() {
  cout << "index: " << index_ << " is mark: " << is_mark_ << " flag: " <<
       flag_ << " addr: " << addr_ << " val: " << val_ << endl;
}