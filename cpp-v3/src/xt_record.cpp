#include "xt_record.h"
#include "xt_util.h"

#include <iostream>

using namespace std;

Record::Record(uint32_t index) {
  index_ = index;
}

bool Record::init_record(const std::string &s_rec) {
  if(s_rec.empty() ) {
    cout << "init record... : given string is empty" << endl;
    return false;
  }

  vector<string> v_s_rec = util::split(s_rec.c_str(), '\t');

  string flag = v_s_rec[0];
  is_mark_ = util::is_mark(flag);

  if(is_mark_) {
    // src_.print_node();
    string addr = v_s_rec[1];
    string val  = v_s_rec[2];
    src_        = Node(index_, is_mark_, flag, addr, val);
    // src_.print_node();
  } else {
    //    cout << "non mark record" << endl;
    //    for(auto it = v_s_rec.begin(); it != v_s_rec.end(); ++it) {
    //      cout << *it << endl;
    //    }

    string src_addr = v_s_rec[1];
    string src_val  = v_s_rec[2];
    src_            = Node(index_, is_mark_, flag, src_addr, src_val);

    string dst_addr = v_s_rec[4];
    string dst_val  = v_s_rec[5];
    dst_            = Node(index_, is_mark_, flag, dst_addr, dst_val);
  }

  return true;
}

bool Record::is_makr() { return is_mark_; }

void Record::set_index(uint32_t index) { index_ = index; }

uint32_t Record::get_index() { return index_; }

Node Record::get_src_node() { return  src_; }

Node Record::get_dst_node() { return dst_; }

void Record::print_record() {
  cout << "src: ";
  src_.print_node();
  cout << "dst: ";
  dst_.print_node();
}
