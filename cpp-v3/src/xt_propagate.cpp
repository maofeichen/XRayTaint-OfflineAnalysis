#include "xt_propagate.h"
#include "xt_util.h"

#include <iostream>
#include <stdexcept>

using namespace std;

void Propagate::get_taint_prpgt(const Node& src,
                                const uint8_t pos,
                                unordered_set<Node,NodeHash>& prpgt_res)
{
  cout << "Taint propagate..." << endl;
  if(!src.is_mem() ) {
    throw runtime_error("taint propagate: given src is not a memory node.");
  }

  search_propagate(src, pos, prpgt_res);
  memTaintMap_.reset();
  localTempMap_.clear();
  globalTempMap_.clear();
  memValMap_.clear();
}

void Propagate::search_propagate(const Node& src,
                                 const uint8_t pos,
                                 unordered_set<Node,NodeHash>& prpgt_res)
{
  src.print_mem_node();
  uint32_t rec_begin    = src.get_index();

  uint32_t idx_rec      = rec_begin + 1;
  for(; idx_rec < log_.get_size(); idx_rec++) {
    Record rec = log_.get_record(idx_rec);
//    rec.print_record();

    Node src = rec.get_const_src_node();
    Node dst = rec.get_const_dst_node();

    if(!src.is_mark() ) {
      char taint_pos = 0;
      if(handle_source_node(src, taint_pos) ) {

      }
    } else if(is_insn_mark(src.get_flag() ) ) {
      localTempMap_.clear();
    }
  }
}

bool Propagate::handle_source_node(Node &node, char &taint_pos)
{
  bool is_valid_prpgt   = false;

  string flag = node.get_flag();
  string addr = node.get_addr();

  if(is_load(flag) ) {
    is_valid_prpgt  = handle_source_node_mem(node, taint_pos);
  }

  return is_valid_prpgt;
}

bool Propagate::handle_source_node_mem(Node &node, char &taint_pos)
{

}


bool Propagate::is_insn_mark(const std::string& flag)
{
  if(util::equal_mark(flag, flag::XT_INSN_ADDR) ) { return true; }
  else { return false; }
}

bool Propagate::is_load(const std::string& flag)
{
  if(util::equal_mark(flag, flag::TCG_QEMU_LD) ) { return true; }
  else { return false; }
}
