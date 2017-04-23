#include "xt_avalanche.h"
#include "xt_blockdetector.h"
#include "xt_flag.h"
#include "xt_propagate.h"
#include "xt_node.h"

#include <algorithm>
#include <map>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_set>
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

          if(it_in->get_begin() == 0x804c860
             && it_in->get_byte_sz() == 96
             && it_out->get_begin() == 0x804d040
             && it_out->get_byte_sz() == 96) {
            detect_in_out(*it_in, *it_out);
          }
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

  vector<vector<Prpgt_Byte_> > in_prpgt_res;
  gen_in_byte_prpgt(in, in_prpgt_res);

//  for(uint32_t idx_byte = 0; idx_byte < in_prpgt_res.size(); idx_byte++) {
//    cout << "idx byte: " << idx_byte << endl;
//    for(auto it_prpgt = in_prpgt_res[idx_byte].begin();
//        it_prpgt != in_prpgt_res[idx_byte].end(); ++it_prpgt) {
//      cout << "propagate to: addr: " << hex << it_prpgt->addr
//           << " val: " << it_prpgt->val << endl;
//    }
//  }

  cout << "num gen taint sources: " << dec << in_prpgt_res.size() << endl;
  if(in_prpgt_res.size() != in.get_byte_sz() ) {
    throw runtime_error("err: num gen taint sources does not match.");
  }

  vector<TaintPropagate *> in_prpgt_ra_res;
  gen_in_taint_ra(in, in_prpgt_res, in_prpgt_ra_res);

  RangeArray      in_blocks;
  VSPtrRangeArray in_blocks_prpgt;
  BlockDetector   block_detector(in.get_begin(), in.get_byte_sz(),
                                 out.get_begin(), out.get_byte_sz() );
  block_detector.detect_block(in_blocks, in_blocks_prpgt, in_prpgt_ra_res);
}

void
Avalanche::gen_in_byte_prpgt(const ContinueBuf& in,
                             vector<vector<Prpgt_Byte_> >& in_prpgt_res)
{
  vector<Multi_Taint_Src_> in_taint_src;
  gen_in_taint_src(in, in_taint_src);

  if(in_taint_src.size() != in.get_byte_sz() ) {
    throw runtime_error("gen in byte propagate: size of taint sources and \
        input size are not matched.");
  }

  cout << "begin addr: " << hex << in.get_begin() << endl;

  for(uint32_t idx_byte = 0; idx_byte < in_taint_src.size(); idx_byte++) {
//    cout << "byte idx: " << idx_byte
//         << " num node: " << in_taint_src[idx_byte].v_taint_src.size()  << endl;
    unordered_set<Node, NodeHash> set_prpgt_res;

    for(auto it = in_taint_src[idx_byte].v_taint_src.begin();
        it != in_taint_src[idx_byte].v_taint_src.end(); ++it) {
      uint32_t node_idx = it->node_idx;
      uint8_t  pos      = it->pos;
//      cout << "node idx: " << node_idx << endl;

      // searches propagate of node index
      Node node = get_mem_node(node_idx);
      unordered_set<Node,NodeHash> prpgt_res;
      prpgt_.get_taint_prpgt(node, pos, prpgt_res);

      merge_prpgt_res(prpgt_res, set_prpgt_res);
    }

    vector<Prpgt_Byte_> v_prpgt_byte;
    to_prpgt_byte(set_prpgt_res, v_prpgt_byte);
//    for(auto it = v_prpgt_byte.begin(); it != v_prpgt_byte.end(); ++it) {
//      it->print_prpgt_byte();
//    }

    in_prpgt_res.push_back(v_prpgt_byte);
  }
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
//    cout << "-----------" << endl;
//    cout << "src addr: " << hex << in_taint_src[i].addr << endl;
//    cout << "num node idx: " << dec << in_taint_src[i].v_taint_src.size() << endl;

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

void
Avalanche::gen_in_taint_ra(const ContinueBuf& in,
                           const vector<vector<Prpgt_Byte_> >& in_prpgt_res,
                           vector<TaintPropagate *>& in_prpgt_ra_res)
{
  cout << "generating range arrays of input buffer..." << endl;

  uint32_t begin_addr   = in.get_begin();
  for(auto it = in_prpgt_res.begin(); it != in_prpgt_res.end(); ++it) {
    TaintPropagate* taint_prpgt = new TaintPropagate(begin_addr);

    gen_in_taint_ra_per_byte(*it, taint_prpgt->get_taint_propagate() );

    in_prpgt_ra_res.push_back(taint_prpgt);
    begin_addr++;
  }

//  for(uint32_t i = 0; i < in_prpgt_ra_res.size(); i++) {
//    cout << "taint src: " << hex << in_prpgt_ra_res[i]->get_src_addr()
//         << " can propagate to: " << endl;
//    for(uint32_t j = 0; j < in_prpgt_ra_res[i]->get_taint_propagate()->get_size(); j++) {
//      in_prpgt_ra_res[i]->get_taint_propagate()->at(j)->print_range();
//      in_prpgt_ra_res[i]->get_taint_propagate()->at(j)->print_byte_val_map();
//    }
//  }

}

void
Avalanche::gen_in_taint_ra_per_byte(const vector<Prpgt_Byte_>& byte_prpgt_res,
                                    RangeArray *byte_taint_prpgt)
{
  if(byte_prpgt_res.empty() ) {
    throw runtime_error("err: gen range arrays per byte, given byte propagation is empty.");
  }

  auto it_prpgt_byte  = byte_prpgt_res.begin();
  uint32_t ra_begin   = it_prpgt_byte->addr;
  uint32_t ra_len     = 1;
  uint32_t ra_val     = stoul(it_prpgt_byte->val, nullptr, 16);

  multimap<uint32_t, uint32_t> byte_val_map;
  byte_val_map.insert(pair<uint32_t,uint32_t>(ra_begin, ra_val) );

  for(it_prpgt_byte++; it_prpgt_byte != byte_prpgt_res.end(); ++it_prpgt_byte) {
    uint32_t curr_range   = ra_begin + ra_len;
    uint32_t curr_addr    = it_prpgt_byte->addr;

    if(curr_range > curr_addr) {
      uint32_t byte_val = stoul(it_prpgt_byte->val, nullptr, 16);
      byte_val_map.insert(pair<uint32_t,uint32_t>(curr_addr, byte_val) );
    } else if(curr_range == curr_addr) {
      uint32_t byte_val = stoul(it_prpgt_byte->val, nullptr, 16);
      byte_val_map.insert(pair<uint32_t,uint32_t>(curr_addr, byte_val) );
      ra_len++;
    } else {
      byte_taint_prpgt->add_range(ra_begin, ra_len, byte_val_map);

      ra_begin    = curr_addr;
      ra_len      = 1;
      ra_val      = stoul(it_prpgt_byte->val, nullptr, 16);
      byte_val_map.clear();
      byte_val_map.insert(pair<uint32_t,uint32_t>(ra_begin, ra_val) );
    }
  }
}

void
Avalanche::merge_prpgt_res(unordered_set<Node,NodeHash> &prpgt_res,
                           unordered_set<Node,NodeHash> &set_prpgt_res)
{
  unordered_set<Node, NodeHash>::const_iterator it_prpgt_res;
  unordered_set<Node, NodeHash>::const_iterator got_multi;

  it_prpgt_res = prpgt_res.begin();
  for (; it_prpgt_res != prpgt_res.end(); ++it_prpgt_res) {
    got_multi = set_prpgt_res.find(*it_prpgt_res);

    if (got_multi == set_prpgt_res.end()) {
      set_prpgt_res.insert(*it_prpgt_res);
    }
  }
}

void
Avalanche::to_prpgt_byte(unordered_set<Node,NodeHash> &set_propagate_res,
                         vector<Prpgt_Byte_>& v_prpgt_byte)
{
  Prpgt_Byte_ prpgt_byte;

  for(auto it = set_propagate_res.begin(); it != set_propagate_res.end(); ++it) {
    prpgt_byte.addr = it->get_int_addr();
    prpgt_byte.val  = it->get_val();
    v_prpgt_byte.push_back(prpgt_byte);
  }

  sort(v_prpgt_byte.begin(), v_prpgt_byte.end() );
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

