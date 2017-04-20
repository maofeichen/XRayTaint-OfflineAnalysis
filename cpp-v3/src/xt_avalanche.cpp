#include "xt_avalanche.h"
#include "xt_flag.h"
#include "xt_node.h"

#include <iostream>
#include <stdexcept>
#include <vector>

using namespace std;

void
Avalanche::detect(const std::vector<AliveFunction>& v_liveness)
{
  cout << "detecting avalanches..." << endl;

  // uses each buffer in each function call as input buffer,
  // its next function calls' buffers as output buffer,
  // search avalanches
  auto it_func_in = v_liveness.end()-2;
//  auto it_func_in = v_liveness.begin();
  for(; it_func_in != v_liveness.end()-1; ++it_func_in) {

    auto it_func_out = it_func_in+1;
    for(; it_func_out != v_liveness.end(); ++it_func_out) {

      auto it_in = it_func_in->get_cont_buf().begin();
      for(; it_in != it_func_in->get_cont_buf().end(); ++it_in) {

        auto it_out = it_func_out->get_cont_buf().begin();
        for(; it_out != it_func_out->get_cont_buf().end(); ++it_out) {
          detect_in_out(*it_in, *it_out);
        }
      }
    }
  }
}

void
Avalanche::detect_in_out(const ContinueBuf& in,
                         const ContinueBuf& out)
{
  cout << "-----------" << endl;
  cout << "detecting input and output avalanches..." << endl;
  cout << "in: ";
  in.print_cont_buf_noidx();
  cout << "out: ";
  out.print_cont_buf_noidx();

  gen_in_byte_prpgt(in);

}

void
Avalanche::gen_in_byte_prpgt(const ContinueBuf& in)
{
  vector<Multi_Taint_Src_> in_taint_src;
  gen_in_taint_src(in, in_taint_src);
}

void
Avalanche::gen_in_taint_src(const ContinueBuf& in,
                            vector<Multi_Taint_Src_>& in_taint_src)
{
  uint32_t begin_addr   = in.get_begin();
  uint32_t byte_sz      = in.get_byte_sz();

  for(uint32_t idx_byte = 0; idx_byte < byte_sz; idx_byte++) {
    uint32_t addr = begin_addr + idx_byte;
//    cout << "addr: " << hex << addr << endl;

    Multi_Taint_Src_ byte_taint_src;
    byte_taint_src.addr = addr;

    for(uint32_t idx_node = 0; idx_node < in.get_node_idx().size(); idx_node++) {
      Node node = get_mem_node(in.get_node_idx().at(idx_node) );
      uint32_t node_addr    = node.get_int_addr();
      uint32_t node_byte_sz = node.get_sz_byte();
//      node.print_mem_node();

      if(node_addr > addr) {
        // if begin address is already larger, then it is impossible that the
        // addr will be in this node range
        break;
      } else {
        if(node_addr + node_byte_sz - 1 >= addr) {
          // the addr is in current node's addr range
          Taint_Src_ t_src;
          uint8_t pos = compute_byte_pos(addr, node);
          t_src.pos   = pos;
          t_src.node_idx = in.get_node_idx().at(idx_node);

          byte_taint_src.v_taint_src.push_back(t_src);
        } else {
          continue;
        }
      }
    } // end for idx_node
    in_taint_src.push_back(byte_taint_src);
  }

  for(uint32_t i = 0; i < in_taint_src.size(); i++) {
    cout << "-----------" << endl;
    cout << "src addr: " << hex << in_taint_src[i].addr << endl;
    cout << "num node idx: " << dec << in_taint_src[i].v_taint_src.size() << endl;

//    for(uint32_t j = 0; j < in_taint_src[i].v_taint_src.size(); j++) {
//      uint32_t node_idx = in_taint_src[i].v_taint_src[j].node_idx;
//      uint8_t  pos      = in_taint_src[i].v_taint_src[j].pos;
//
//      Node node = get_mem_node(node_idx);
//      node.print_mem_node();
//      cout << "byte pos: " << unsigned(pos) << endl;
//    }
  }
}

Node
Avalanche::get_mem_node(uint32_t idx)
{
  Node node;
  Record rec = log_.get_record(idx);
  if(rec.is_mem_type(flag::M_LOAD) ) {
    node = rec.get_const_src_node();
  } else if(rec.is_mem_type(flag::M_STORE) ) {
    node = rec.get_const_dst_node();
  } else {
    throw runtime_error("get mem node: given node is not mem type.");
  }
//  cout << "log size: " << log_.get_size() << endl;
//  rec.print_record();
  return node;
}

uint8_t
Avalanche::compute_byte_pos(const uint32_t addr, const Node& node)
{
  uint8_t  pos = 0;
  uint32_t node_begin  = node.get_int_addr();
  uint8_t  node_sz     = node.get_sz_byte();

  for(uint32_t i = 0; i < node_sz; i++) {
    if(addr == node_begin + i) {
      pos = i;
      break;
    }
  }

  return pos;
}

