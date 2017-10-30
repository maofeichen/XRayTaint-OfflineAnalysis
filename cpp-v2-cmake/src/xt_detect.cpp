#include "xt_aval_in_out.h"
#include "xt_blockdetect.h"
#include "xt_blockmodedetector.h"
#include "xt_cbcdetector.h"
#include "xt_ByteTaintPropagate.h"
#include "xt_detect.h"
#include "xt_flag.h"
#include "xt_util.h"

#include <algorithm>
#include <map>
#include <string>
#include <iostream>

using namespace std;

Detect::Detect(vector<t_AliveFunctionCall> v_func_cont_buf,
		       XTLog &xt_log,
		       vector<Record> log_rec)
{
    v_func_cont_buf_ = v_func_cont_buf;
    xt_log_ = xt_log;
    log_rec_ = log_rec;
}

void Detect::detect_cipher() {
  cout << "Detecting cipher after liveness analysis..." << endl;

  Propagate propagate(xt_log_);

  // Store which IN and OUT buffer had been searched already
  vector<pair_inout_> v_buf_in_out;

//  vector<t_AliveFunctionCall>::iterator it_in_func = v_func_cont_buf_.end() - 2;
   vector<t_AliveFunctionCall>::iterator it_in_func = v_func_cont_buf_.begin();

  // Iterates each function call
  for (; it_in_func != v_func_cont_buf_.end() - 1; ++it_in_func) {
    vector<t_AliveFunctionCall>::const_iterator it_out_func = it_in_func + 1;

    for (; it_out_func != v_func_cont_buf_.end(); ++it_out_func) {
      // Iterates each continuous buffer in each function call
      vector<t_AliveContinueBuffer>
          v_in_buf = (*it_in_func).vAliveContinueBuffer;
      vector<t_AliveContinueBuffer>::const_iterator
          it_in_buf = v_in_buf.begin();

      for (; it_in_buf != v_in_buf.end(); ++it_in_buf) {
        vector<t_AliveContinueBuffer>
            v_out_buf = (*it_out_func).vAliveContinueBuffer;
        vector<t_AliveContinueBuffer>::const_iterator
            it_out_buf = v_out_buf.begin();

        for (; it_out_buf != v_out_buf.end(); ++it_out_buf) {
          if ((*it_in_buf).beginAddress != (*it_out_buf).beginAddress) {
            t_AliveContinueBuffer in_buf = *it_in_buf;
            t_AliveContinueBuffer out_buf = *it_out_buf;

            pair_inout_ buf_in_out;

            buf_in_out.in_.beginAddress   = in_buf.beginAddress;
            buf_in_out.in_.size           = in_buf.size;
            buf_in_out.out_.beginAddress  = out_buf.beginAddress;
            buf_in_out.out_.size          = out_buf.size;

            if (is_dupl_buf_inout(buf_in_out, v_buf_in_out)) {
              cout << "In and Out buffers had been searched, skip..." << endl;
            } else {
//              v_buf_in_out.push_back(buf_in_out);

              cout << "in: addr: " << hex << in_buf.beginAddress
                   << " byte: " << dec << in_buf.size / 8 << endl;
              cout << "out: addr: " << hex << out_buf.beginAddress
                   << " byte: " << dec << out_buf.size / 8 << endl;
              bool is_det = false;
//              is_det = detect_cipher_in_out(in_buf, out_buf, propagate);
              if(is_det) {
                cout << "successfully detects cipher" << endl;
              }

              /* if (in_buf.beginAddress == 0xe5515000 &&
                  in_buf.size == 92 * 8*/ /* &&
                  out_buf.beginAddress == 0xbfffee8c*/ /*&&
                  out_buf.size == 92 * 8 ) { */

              if(in_buf.beginAddress == 0xdc99a100 && in_buf.size == 1024 * 8
                  && out_buf.beginAddress == 0x804c270 && out_buf.size == 1024 * 8) {

//                int num_source = in_buf.vNodeIndex.size();
//                cout << "number of source index in the input buffer: "
//                     << dec << in_buf.vNodeIndex.size() << endl;
//
                detect_cipher_in_out(in_buf, out_buf, propagate);

//                if (num_source == 24) {
//                  vector<unsigned long>::const_iterator it_n_idx =
//                      it_in_buf->vNodeIndex.begin();
//                  for (; it_n_idx != it_in_buf->vNodeIndex.end(); ++it_n_idx) {
//                    cout << "src index: " << dec << *it_n_idx << endl;
//                    XTNode node = get_mem_node(*it_n_idx);
//                    cout << "node addr: " << hex << node.getIntAddr() << endl;
//                  }
//
//                  detect_cipher_in_out(in_buf, out_buf, propagate);
//                }
              }
            }
          }
        }
      }
    }
  }
}

inline unsigned long
Detect::comp_multi_src_interval(vector<unsigned long> &v_node_idx,
								vector<unsigned long>::const_iterator it_node_idx)
{
    unsigned long count = 1;

    XTNode node = get_mem_node(*it_node_idx);
    unsigned long begin_addr = node.getIntAddr();

    for(it_node_idx++; it_node_idx != v_node_idx.end(); ++it_node_idx){
        node = get_mem_node(*it_node_idx);

        cout << "node index: " << dec << *it_node_idx << endl;
        cout << "node addr: " << hex << node.getIntAddr() << endl;

        if(begin_addr != node.getIntAddr() ){
           break;
        }

        count++;
    }

    return count;
}

inline string Detect::get_insn_addr(unsigned long idx, std::vector<Record> &v_rec)
{
    while(idx > 0){
        if(v_rec[idx].isMark &&
           XT_Util::equal_mark(v_rec[idx].regular.src.flag, flag::XT_INSN_ADDR) ){
            return v_rec[idx].regular.src.addr;
        }
        idx--;
    }
    return "";
}

inline void
Detect::merge_propagate_res(unordered_set<Node, NodeHash> &propagate_res,
	                        unordered_set<Node, NodeHash> &multi_propagate_res)
{
    unordered_set<Node, NodeHash>::const_iterator it_propagate_res;
    unordered_set<Node, NodeHash>::const_iterator got_multi;

    it_propagate_res = propagate_res.begin();
    for(; it_propagate_res != propagate_res.end(); ++it_propagate_res){
        got_multi = multi_propagate_res.find(*it_propagate_res);

        if( got_multi == multi_propagate_res.end() ){
            multi_propagate_res.insert(*it_propagate_res);
        }
    }
}

inline bool
Detect::is_dupl_buf_inout(Detect::pair_inout_ &bufInOut, std::vector<Detect::pair_inout_> &vBufInOut)
{
    if(vBufInOut.empty() ){
		return false;
    }

	for(vector<Detect::pair_inout_>::iterator it = vBufInOut.begin(); it != vBufInOut.end(); ++it){
		if(it->in_.beginAddress == bufInOut.in_.beginAddress&&
		   it->in_.size == bufInOut.in_.size &&
		   it->out_.beginAddress == bufInOut.out_.beginAddress &&
		   it->out_.size == bufInOut.out_.size)
			return true;
	}

	return false;
}

unordered_set<Node, NodeHash>
Detect::comp_multi_src_propagate_res(unsigned int multi_src_interval,
                                     vector<unsigned long>::const_iterator it_multi_src_idx,
                                     unsigned int byte_pos,
                                     Propagate &propagate)
{

    unordered_set<Node, NodeHash> propagate_res;
    unordered_set<Node, NodeHash> multi_propagate_res;

    for(uint32_t i = 0; i < multi_src_interval; i++){
        XTNode node = get_mem_node(*it_multi_src_idx);
        NodePropagate taint_src = init_taint_source(node, log_rec_);
        propagate_res = propagate.getPropagateResult(taint_src, log_rec_, byte_pos);
        merge_propagate_res(propagate_res, multi_propagate_res);

        it_multi_src_idx++;
    }

    return multi_propagate_res;
}

vector<Detect::propagate_byte_>
Detect::convert_propagate_byte(unordered_set<Node, NodeHash> &multi_propagate_res)
{
  vector<propagate_byte_> v_propagate_byte;
  propagate_byte_ propagate_byte;

  unordered_set<Node, NodeHash>::const_iterator it_multi;

  it_multi = multi_propagate_res.begin();
  // Only needs addr and val, size is 1 byte by default
  for (; it_multi != multi_propagate_res.end(); ++it_multi) {
    propagate_byte.addr = (*it_multi).i_addr;
    propagate_byte.val = (*it_multi).val;
    v_propagate_byte.push_back(propagate_byte);
  }

  sort(v_propagate_byte.begin(), v_propagate_byte.end() );
  return v_propagate_byte;
}

vector< vector<Detect::propagate_byte_> >
Detect::gen_in_propagate_byte(t_AliveContinueBuffer &in, Propagate &propagate)
{
    vector< vector<propagate_byte_> > in_vec_propagate_byte;

    for(int i = 0; i < in.vNodeIndex.size(); i++) {
      uint32_t idx = in.vNodeIndex[i];
      XTNode n = get_mem_node(idx);
      cout << "node addr: " << hex << n.getIntAddr() << " size: " << dec
           << n.getByteSize() << endl;
    }

    unsigned int byte_pos    = 0;
    unsigned long begin_addr = in.beginAddress;
    vector<unsigned long>::const_iterator it_node_idx;

    it_node_idx = in.vNodeIndex.begin();
    while(it_node_idx != in.vNodeIndex.end() ){
        unsigned int multi_src_interval;
        vector<unsigned long>::const_iterator it_multi_src_idx;
        unordered_set<Node, NodeHash> multi_propagate_res;

        cout << "Search taint propagation: taint source: " << hex << begin_addr << endl;
        multi_src_interval = comp_multi_src_interval(in.vNodeIndex, it_node_idx);
        it_multi_src_idx = it_node_idx;
        multi_propagate_res = comp_multi_src_propagate_res(multi_src_interval,
                                                           it_multi_src_idx,
                                                           byte_pos, propagate);

        vector<propagate_byte_> v_propagate_byte;
        v_propagate_byte = convert_propagate_byte(multi_propagate_res);
        in_vec_propagate_byte.push_back(v_propagate_byte);

        byte_pos++;
        begin_addr++;

        // if crosses 4 bytes, reset and goes to next multi sources
        XTNode node = get_mem_node(*it_node_idx);
        switch(node.getByteSize() ){
            case 4:
                if(byte_pos > 3){
                    byte_pos = 0;
                    it_node_idx += multi_src_interval;
                }
                break;
            case 2:
                if(byte_pos > 2){
                    byte_pos = 0;
                    it_node_idx += multi_src_interval;
                }
                break;
            case 1:
                byte_pos = 0;
                it_node_idx += multi_src_interval;
                break;
            default:
                cout << "error: incorrect mem node size" << endl;
        }

        // if(byte_pos > 3 ){
        //     byte_pos = 0;
        //     it_node_idx += multi_src_interval;
        // }
    }

    return in_vec_propagate_byte;
}

vector<vector<Detect::propagate_byte_> > Detect::gen_in_prpgt_byte(
    t_AliveContinueBuffer &in,
    Propagate &propagate)
{
  vector< vector<propagate_byte_> > v_in_prpgt_byte;

  vector<Detect::Multi_Taint_Source_> v_taint_src;
  v_taint_src = gen_taint_source(in);

  if(v_taint_src.size() != in.size / 8) {
    cout << "err: generated byte propagation is not matched size of input buf"
         << endl;
  }

  for(int byte_idx = 0; byte_idx < v_taint_src.size(); byte_idx++) {
    unordered_set<Node, NodeHash> multi_prpgt_res;

    for(int node_idx = 0; node_idx < v_taint_src[byte_idx].v_multi_src.size()
        ; node_idx++) {
      uint32_t curr_node_idx = v_taint_src[byte_idx].v_multi_src[node_idx].node_idx;
      uint8_t curr_pos       = v_taint_src[byte_idx].v_multi_src[node_idx].pos;

      XTNode node = get_mem_node(curr_node_idx);
      NodePropagate taint_src = init_taint_source(node, log_rec_);

      unordered_set<Node, NodeHash> prpgt_res;
      prpgt_res = propagate.getPropagateResult(taint_src, log_rec_, curr_pos);

      merge_propagate_res(prpgt_res, multi_prpgt_res);
    }

    vector<propagate_byte_> v_prpgt_byte;
    v_prpgt_byte = convert_propagate_byte(multi_prpgt_res);
    v_in_prpgt_byte.push_back(v_prpgt_byte);
  }

  return v_in_prpgt_byte;
}

void Detect::gen_range_array_per_byte(vector<Detect::propagate_byte_> v_propagate_byte,
                                      RangeArray *range_array)
{
    if(v_propagate_byte.empty() ){
        cout << "error: gen range array per byte, give vector of propagated "
            "bytes is empty" << endl;
        return;
    }

    sort(v_propagate_byte.begin(), v_propagate_byte.end() );

    vector<propagate_byte_>::const_iterator it_propagate_byte =
        v_propagate_byte.begin();
    // it_propagate_byte = v_propagate_byte.begin();

    unsigned long range_begin_addr = (*it_propagate_byte).addr;
    unsigned int range_len = 1;


    for(; it_propagate_byte != v_propagate_byte.end(); ++it_propagate_byte){
        unsigned long curr_addr = (*it_propagate_byte).addr;

        if(range_begin_addr + range_len == curr_addr){
            range_len++;
        }
        else if(range_begin_addr + range_len < curr_addr){
            // cout << "a new range, previous range: " <<
            //         "addr: " << hex << range_begin_addr <<
            //         " len: " << dec << range_len << " bytes" << endl;

            range_array->add_range(range_begin_addr, range_len);

            // Init for next range
            range_begin_addr = curr_addr;
            range_len = 1;
        }
    }
    // range_array.disp_range_array();
}

void Detect::gen_range_array_per_byte_with_val(vector<Detect::propagate_byte_> v_propagate_byte,
                                               RangeArray *range_array) {
  if (v_propagate_byte.empty()) {
    cout << "error: gen range array per byte, give vector of propagated "
        "bytes is empty" << endl;
    return;
  }

  sort(v_propagate_byte.begin(), v_propagate_byte.end());
//  for(auto it = v_propagate_byte.begin(); it != v_propagate_byte.end(); ++it) {
//    cout << "propagated addr: " << hex << it->addr << " val: " << it->val
//         << endl;
//  }

  vector<propagate_byte_>::const_iterator it_propagate_byte =
      v_propagate_byte.begin();

  uint32_t r_begin_addr = it_propagate_byte->addr;
  uint32_t r_len        = 1;
  uint32_t r_val        = stoul(it_propagate_byte->val, nullptr, 16);

  std::multimap<uint32_t, uint32_t> byte_val_map;
  byte_val_map.insert(pair<uint32_t, uint32_t>(r_begin_addr, r_val) );

  for(it_propagate_byte += 1; it_propagate_byte != v_propagate_byte.end();
      ++it_propagate_byte) {
    uint32_t curr_range = r_begin_addr + r_len;
    uint32_t curr_addr = it_propagate_byte->addr;

//    cout << "current range: " << hex << curr_range << endl;
//    cout << "current addr: " << hex << curr_addr << endl;
    if(curr_range > curr_addr) {
      // multi values for same propagated byte
      uint32_t byte_val = stoul(it_propagate_byte->val, nullptr, 16);
      byte_val_map.insert(pair<uint32_t,uint32_t>(curr_addr, byte_val) );

//      cout << "byte val: " << it_propagate_byte->val << endl;
//      cout << "byte val in hex: " << hex << byte_val << endl;
    } else if (curr_range == curr_addr) {
      // next continuous byte
      uint32_t byte_val = stoi(it_propagate_byte->val, nullptr, 16);
      byte_val_map.insert(pair<uint32_t,uint32_t>(curr_addr, byte_val) );
      // r.add_byte_val(curr_addr, byte_val);
      r_len++;

//      cout << "byte val: " << it_propagate_byte->val << endl;
//      cout << "byte val in hex: " << hex << byte_val << endl;
    } else {
      // range smaller than current addr
      range_array->add_range(r_begin_addr, r_len, byte_val_map);
//      range_array->at(0)->disp_range();
//      range_array->at(0)->disp_byte_val_map();

      r_begin_addr = curr_addr;
      r_len        = 1;
      r_val        = stoul(it_propagate_byte->val, nullptr, 16);
      byte_val_map.clear();
      byte_val_map.insert(pair<uint32_t,uint32_t>(r_begin_addr, r_val) );
    }
  }

//  for(int i = 0; i < range_array->get_size(); i++) {
//    range_array->at(i)->disp_range();
//    range_array->at(i)->disp_byte_val_map();
//  }

}

void Detect::gen_in_range_array(t_AliveContinueBuffer &in,
                                vector<vector<Detect::propagate_byte_> > &in_vec_propagate_byte,
                                vector<ByteTaintPropagate *> &in_taint_propagate) {
  cout << "generating range arrays of input buffer..." << endl;

  // vector<RangeArray *> v_range_array;
  unsigned long begin_addr = in.beginAddress;
  vector<vector<propagate_byte_> >::const_iterator it_in_byte;

  it_in_byte = in_vec_propagate_byte.begin();
  for (; it_in_byte != in_vec_propagate_byte.end(); ++it_in_byte) {
    // RangeArray *range_array = new RangeArray();
    // gen_range_array_per_byte(*it_in_byte, range_array);
    // range_array->disp_range_array();
    // v_range_array.push_back(range_array);

    ByteTaintPropagate *byte_taint_propagate =
        new ByteTaintPropagate(begin_addr);
//    gen_range_array_per_byte(*it_in_byte,
//                             byte_taint_propagate->get_taint_propagate());
    gen_range_array_per_byte_with_val(*it_in_byte,
                                      byte_taint_propagate->get_taint_propagate() );

    // byte_taint_propagate->get_taint_propagate()->disp_range_array();

    in_taint_propagate.push_back(byte_taint_propagate);
    begin_addr++;
  }

//  for(int i = 0; i < in_taint_propagate.size(); i++){
//    cout << "byte addr: " << hex << in_taint_propagate[i]->get_taint_src()
//         << " can propagate to ranges: " << endl;
//    for(int j = 0; j < in_taint_propagate[i]->get_taint_propagate()->get_size
//        (); j++) {
//      in_taint_propagate[i]->get_taint_propagate()->at(j)->disp_range();
//      in_taint_propagate[i]->get_taint_propagate()->at(j)->disp_byte_val_map();
//    }
//  }
}

vector<Detect::Multi_Taint_Source_> Detect::gen_taint_source(const t_AliveContinueBuffer &in)
{
  vector<Detect::Multi_Taint_Source_> v_taint_src;

  uint32_t begin_addr = in.beginAddress;
  uint32_t buf_sz     = in.size / 8;

  for(uint32_t byte_idx = 0; byte_idx < buf_sz; byte_idx++) {
    uint32_t addr = begin_addr + byte_idx;
    Multi_Taint_Source_ multi_taint_src;
    multi_taint_src.addr = addr;

    for(int node_idx = 0; node_idx < in.vNodeIndex.size(); node_idx++) {
      XTNode node = get_mem_node(in.vNodeIndex[node_idx]);
      uint32_t node_begin = node.getIntAddr();
      uint32_t node_sz    = node.getByteSize();

      if(node_begin > addr) {
        // if begin address is already larger, then it is impossible that the
        // addr will be in this node range
        break;
      }

      if (node_begin <= addr) {
        if (node_begin + node_sz - 1 >= addr) {
          // addr is in this node range
          uint8_t pos = compute_byte_pos(addr, node);
          Taint_Source_ taint_source_;
          taint_source_.node_idx = in.vNodeIndex[node_idx];
          taint_source_.pos = pos;

          multi_taint_src.v_multi_src.push_back(taint_source_);
        } else {
          continue;
        }
      }
    }

    v_taint_src.push_back(multi_taint_src);
  }

  for(int i = 0; i < v_taint_src.size(); i++) {
    cout << "source addr: " << hex << v_taint_src[i].addr << endl;
    for(int j = 0; j < v_taint_src[i].v_multi_src.size(); j++) {
      uint32_t node_idx = v_taint_src[i].v_multi_src[j].node_idx;
      uint8_t pos = v_taint_src[i].v_multi_src[j].pos;

      XTNode node = get_mem_node(node_idx);
      cout << "src node addr: " << hex << node.getIntAddr()
           << " size: " << dec << node.getByteSize()
           << " pos: " <<  dec << unsigned(pos) << endl;
    }
  }
  return v_taint_src;
}

XTNode Detect::get_mem_node(unsigned long index)
{
    XTNode node, src_node;
    XTRecord rec = xt_log_.getRecord(index);
    string src_flag;

    src_node = rec.getSourceNode();
    src_flag = src_node.getFlag();
    if(XT_Util::equal_mark(src_flag, flag::TCG_QEMU_LD) ){
        node = src_node;
    }else if(XT_Util::equal_mark(src_flag, flag::TCG_QEMU_ST) ){
        node = rec.getDestinationNode();
    }else{
        cout << "error: get_mem_node: record index: " << index
                << " is neither load or store..." << endl;
    }

    return node;
}

NodePropagate
Detect::init_taint_source(XTNode &node, std::vector<Record> &log_rec)
{
    NodePropagate src;

    string src_flag = node.getFlag();
    if(XT_Util::equal_mark(src_flag, flag::TCG_QEMU_LD) ){
        src.isSrc = true;
        src.id    = node.getIndex() * 2;
    }else if(XT_Util::equal_mark(src_flag, flag::TCG_QEMU_ST) ){
        src.isSrc = false;
        src.id    = node.getIndex() * 2 + 1;
    }else{
        cout << "error: init_taint_source: given node is neither load or store..."
                << endl;
    }

    src.parentId    = 0;
    src.layer       = 0;
    unsigned long rec_idx = node.getIndex();
    src.pos         = rec_idx;
    src.insnAddr    = get_insn_addr(rec_idx, log_rec_);
    src.n.flag      = node.getFlag();
    src.n.addr      = node.getAddr();
    src.n.val       = node.getVal();
    src.n.i_addr    = node.getIntAddr();
    src.n.sz        = node.getBitSize();

    return src;
}

uint8_t Detect::compute_byte_pos(uint32_t addr, XTNode &node)
{
  uint8_t pos = 0;
  uint32_t node_begin = node.getIntAddr();
  uint8_t node_sz     = node.getByteSize();

  for(int i = 0; i < node_sz; i++) {
    if(addr == node_begin + i) {
      pos = i;
      break;
    }
  }

  return pos;
}

bool Detect::detect_cipher_in_out(t_AliveContinueBuffer &in,
                                  t_AliveContinueBuffer &out,
                                  Propagate &propagate) {
  // Aval_In_Out aval_in_out(in, out);

  vector<vector<propagate_byte_> > v_in_propagated_byte;
//  vector<vector<propagate_byte_> > v_in_propagated_byte_test;

//  v_in_propagated_byte_test = gen_in_propagate_byte(in, propagate);
  v_in_propagated_byte = gen_in_prpgt_byte(in, propagate);

//  if(v_in_propagated_byte.size() == v_in_propagated_byte_test.size() ) {
//    for(int i = 0; i < v_in_propagated_byte.size(); i++) {
//      if(v_in_propagated_byte[i].size() == v_in_propagated_byte_test[i].size() ) {
//        for(int j = 0; j < v_in_propagated_byte[i].size(); j++) {
//          cout << "addr: " << hex <<  v_in_propagated_byte[i][j].addr
//               << " val: " << v_in_propagated_byte[i][j].val << endl;
//
//          cout << "test addr: " << hex << v_in_propagated_byte_test[i][j].addr
//               << " val: " << v_in_propagated_byte_test[i][j].val << endl;
//        }
//      }
//    }
//  }

  cout << "numbef of bytes in in buffer: " << dec << in.size / 8 << endl;
  cout << "number of vector of propagte bytes: " << dec
       << v_in_propagated_byte.size() << endl;
  if ((in.size / 8) != v_in_propagated_byte.size()) {
    cout << "err: num of bytes of input, and num of propagated bytes is "
        "not matched" << endl;
    return false;
  }

  vector<ByteTaintPropagate *> v_in_taint_propagate;
  gen_in_range_array(in, v_in_propagated_byte, v_in_taint_propagate);

  for (int i = 0; i < v_in_taint_propagate.size(); i++) {
    cout << "taint src: " << hex << v_in_taint_propagate[i]->get_taint_src()
         << endl;
    uint32_t addr = v_in_taint_propagate[i]->get_taint_src();
//    if(addr == 0x804b0e0) {
//      cout << "addr: 804b0e0" << endl;
//    }
    for(int j = 0; j < v_in_taint_propagate[i]->get_taint_propagate()
        ->get_size(); j++) {
      v_in_taint_propagate[i]->get_taint_propagate()->at(j)->disp_range();
//      v_in_taint_propagate[i]->get_taint_propagate()->at(j)
//          ->disp_byte_val_map();
    }
  }

  RangeArray input_blocks;
  VSPtrRangeArray input_block_propa;
  BlockDetect block_detector(in.beginAddress, in.size / 8,
                             out.beginAddress, out.size / 8);
  block_detector.detect_block_size(input_blocks, input_block_propa,
                                   v_in_taint_propagate);
  cout << "block detection result: " << endl;
  input_blocks.disp_range_array();
  cout << "blocks propagated ranges: " << endl;
  for(uint32_t i = 0; i < input_block_propa.size(); i++) {
    cout << i+1 << "\tblock ->" << endl;
    input_block_propa[i]->disp_range_array();
  }

  bool is_det = false;
  CFBDetector det_cfb;
  CBCDetector det_cbc(out.beginAddress, out.size / 8);
  is_det = det_cfb.analyze_mode(input_blocks, input_block_propa,
                                v_in_taint_propagate);
  if(det_cfb.get_type() == BlockModeDetector::TYPE_ENC) {
    cout << "cfb enc detected: " << endl;
    det_cfb.get_input().disp_range();
    det_cfb.get_output().disp_range();
  } else if(det_cfb.get_type() == BlockModeDetector::TYPE_DEC) {
    cout << "cfb dec detected: " << endl;
    det_cfb.get_input().disp_range();
    det_cfb.get_output().disp_range();
  } else {
    cout << "no cfb detected" << endl;
  }

  is_det = det_cbc.analyze_mode(input_blocks, input_block_propa,v_in_taint_propagate);
  if(det_cbc.get_type() == BlockModeDetector::TYPE_ENC) {
    cout << "cbc enc detected: " << endl;
    det_cbc.get_input().disp_range();
    det_cbc.get_output().disp_range();
  } else if(det_cbc.get_type() == BlockModeDetector::TYPE_DEC) {
    cout << "cbc dec detected: " << endl;
    det_cbc.get_input().disp_range();
    det_cbc.get_output().disp_range();
  } else {
    cout << "no cbc detected" << endl;
  }

//  is_det = block_detector.detect_mode_type(input_blocks, input_block_propa,
//                                           v_in_taint_propagate);

  return is_det;

  /*
  Blocks blocks;
  BlockDetect block_detect(out.beginAddress, out.size / 8);

  // block_detect.detect_block_size_ori(blocks, v_in_taint_propagate, in.size / 8,
  //                                out.beginAddress, out.size / 8);
  // block_detect.detect_block_size_alter(blocks, v_in_taint_propagate, in.size / 8,
  //                                      out.beginAddress, out.size / 8);
  block_detect.detect_block_sz_small_win(blocks,
                                         v_in_taint_propagate,
                                         in.size / 8,
                                         out.beginAddress,
                                         out.size / 8);

  if (blocks.size() == 0) {
    cout << "No block identified" << endl;
    return;
  }

  block_detect.detect_mode_type_ori(v_in_taint_propagate, blocks);
  */
}
