#include "xt_flag.h"
#include "xt_file.h"
#include "xt_log.h"

#include <iostream>

using namespace std;

Log::Log(const vector<string> &v_s_log) {
  init_log(v_s_log);
}

void Log::analyze_mem_record() {
  if(v_rec_.empty() ) {
    cout << "error: analyze mem record: log is empty" << endl;
    return;
  }

  for(auto it = v_rec_.begin(); it != v_rec_.end(); ++it) {
    if(!it->is_makr() ) {
      string flag = it->get_src_node().get_flag();
      if(flag.empty() ) {
        cout << "error: analyze mem record: flag is empty" << endl;
        return;
      }

      uint32_t i_flag = std::stoi(flag, nullptr, 16);
      if(is_in_mem_range(i_flag) ) {
        analyze_mem_record(i_flag, it);
      }
    }
  }
}

void Log::print_log() {
  if(v_rec_.empty() ) {
    cout << "log is empty" << endl;
    return;
  }

  for(auto it = v_rec_.begin(); it != v_rec_.end(); ++it) {
    it->print_record();
  }
}

uint8_t Log::decode_byte_sz(uint8_t sz_encode) {
  switch (sz_encode) {
    case 1:return 1;
    case 2:return 2;
    case 3:return 4;
    default:
      cout << "error: decode sz: unknown sz encode" << endl;
      return 0;
  }
}

flag::Mem_Type Log::get_mem_type(uint32_t flag) {
  flag::Mem_Type mt;

  if(flag > flag::NUM_TCG_ST_POINTER) {
     mt = flag::M_STORE_PTR;
  } else if(flag > flag::NUM_TCG_ST) {
     mt = flag::M_STORE;
  } else if(flag > flag::NUM_TCG_LD_POINTER) {
     mt = flag::M_LOAD_PTR;
  } else if(flag > flag::NUM_TCG_LD) {
     mt = flag::M_LOAD;
  } else {
    mt = flag::M_UNKNOW;
  }

  return mt;
}

bool Log::is_in_mem_range(uint32_t flag) {
  if(flag >= flag::NUM_TCG_LD_MIN &&
      flag <= flag::NUM_TCG_ST_MAX ) {
    return true;
  } else {
    return false;
  }
}

void Log::update_mem_node(Node node, std::string flag_update, uint8_t sz_byte) {
  string s_addr = node.get_addr();
  if(s_addr.empty() ) {
    cout << "err: update node: node addr is empty" << endl;
    return;
  }

  uint32_t i_addr = stoi(s_addr, nullptr, 16);
  node.set_flag(flag_update);
  node.set_int_addr(i_addr);
  node.set_sz_bit(sz_byte * 8);

  node.print_mem_node();
}

void Log::analyze_mem_record(uint32_t flag,
                             vector<Record>::iterator it_rec) {
  flag::Mem_Type mt = get_mem_type(flag);

  switch (mt) {
    case flag::M_STORE_PTR:
      update_store_ptr(it_rec, flag);
      break;
    case flag::M_STORE:
      update_store(it_rec, flag);
      break;
    case flag::M_LOAD_PTR:
      update_load_ptr(it_rec, flag);
      break;
    case flag::M_LOAD:
      update_load(it_rec, flag);
      break;
    case flag::M_UNKNOW:
      cout << "error: analyze mem record: unknown mem type" << endl;
      break;
  }
}

void Log::update_store_ptr(std::vector<Record>::iterator it_rec,
                           uint32_t flag) {
  it_rec->print_record();
}

void Log::update_store(std::vector<Record>::iterator it_rec, uint32_t flag) {
  it_rec->print_record();

  string flag_update  = flag::TCG_QEMU_ST;
  it_rec->get_src_node().set_flag(flag_update);
  it_rec->get_dst_node().set_flag(flag_update);

  uint8_t sz_encode   = flag - flag::NUM_TCG_ST;
  uint8_t byte_sz     = decode_byte_sz(sz_encode);
  if(byte_sz != 0) {

  } else {
    cout << "update store: error byte sz" << endl;
  }
}

void Log::update_load_ptr(std::vector<Record>::iterator it_rec,
                          uint32_t flag) {
  it_rec->print_record();
}

void Log::update_load(std::vector<Record>::iterator it_rec, uint32_t flag) {
  it_rec->print_record();
}

void Log::init_log(const vector<string> &v_s_log) {
  cout << "init log..." << endl;

  if(v_s_log.empty() ) {
    cout << "init log: given vector of string log is empty..." << endl;
    return;
  }

  uint32_t index = 0;
  for(auto it = v_s_log.begin(); it != v_s_log.end(); ++it) {
    Record rec(index);
    if(rec.init_record(*it) ) {
      v_rec_.push_back(rec);
      index++;
    }
  }
}

