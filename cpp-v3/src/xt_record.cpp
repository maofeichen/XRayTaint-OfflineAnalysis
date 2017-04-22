#include "xt_record.h"
#include "xt_util.h"

#include <iostream>

using namespace std;

Record::Record(uint32_t index) {
  index_ = index;
}

Record::Record(const Record &rhs) {
  index_    = rhs.get_index();
  is_mark_  = rhs.is_makr();
  mt_       = rhs.get_mem_type();
  src_      = rhs.get_const_src_node();
  dst_      = rhs.get_const_dst_node();
}

Record&
Record::operator=(const Record &rhs) {
  index_    = rhs.get_index();
  is_mark_  = rhs.is_makr();
  mt_       = rhs.get_mem_type();
  src_      = rhs.get_const_src_node();
  dst_      = rhs.get_const_dst_node();
  return *this;
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
    src_        = Node(index_, is_mark_, false, true, flag, addr, val);
    // src_.print_node();
  } else {
    //    cout << "non mark record" << endl;
    //    for(auto it = v_s_rec.begin(); it != v_s_rec.end(); ++it) {
    //      cout << *it << endl;
    //    }

    string src_addr = v_s_rec[1];
    string src_val  = v_s_rec[2];
    src_            = Node(index_, is_mark_, false, true, flag, src_addr, src_val);

    string dst_addr = v_s_rec[4];
    string dst_val  = v_s_rec[5];
    dst_            = Node(index_, is_mark_, false, false, flag, dst_addr, dst_val);
  }

  return true;
}

bool Record::is_makr() const { return is_mark_; }

bool Record::is_mem_type(const flag::Mem_Type mt)
{
  if(mt_ == mt) {return true; }
  else { return false; }
}


void Record::set_index(uint32_t index) { index_ = index; }

uint32_t Record::get_index() const { return index_; }

Node &Record::get_src_node() { return src_; }

Node &Record::get_dst_node() { return dst_; }

void Record::print_record() const {
  cout << "----------- -----------" << endl;
  switch(mt_) {
    case flag::M_LOAD:      cout << "mem load"     << endl; break;
    case flag::M_LOAD_PTR:  cout << "mem load ptr" << endl; break;
    case flag::M_STORE:     cout << "mem store"    << endl; break;
    case flag::M_STORE_PTR: cout << "mem store ptr" << endl; break;
    default: break;
  }

  cout << "src: ";
  if(src_.is_mem() ) {
    src_.print_mem_node();
  }else {
    src_.print_node();
  }
  cout << "dst: ";
  if(dst_.is_mem() ) {
    dst_.print_mem_node();
  } else {
    dst_.print_node();
  }
}
