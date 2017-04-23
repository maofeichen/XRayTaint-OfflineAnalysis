#include "xt_constant.h"
#include "xt_propagate.h"
#include "xt_util.h"

#include <stdexcept>

using namespace std;

void Propagate::get_taint_prpgt(const Node& src,
                                const uint8_t pos,
                                unordered_set<Node,NodeHash>& prpgt_res)
{
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
//  src.print_mem_node();
  uint32_t rec_begin    = src.get_index();

  search_propagate_init(src, pos, prpgt_res);

//  uint32_t idx_rec      = rec_begin;
  uint32_t idx_rec      = rec_begin + 1;
  for(; idx_rec < log_.get_size(); idx_rec++) {
    Record rec = log_.get_record(idx_rec);
//    rec.print_record();

    Node src = rec.get_const_src_node();
    Node dst = rec.get_const_dst_node();

    if(!src.is_mark() ) {
      char taint_pos = 0;
      if(handle_source_node(src, taint_pos) ) {
        string flag = src.get_flag();
        // if not bitwise ir, assume all 4 bytes of temp are tainted,
        // results in a overtained to 4 bytes
        if(!is_bitwise_ir(flag) ) {
          taint_pos = 15;
        }

        handle_destinate_node(dst, taint_pos, false, prpgt_res);
      } else {}
    } else if(is_insn_mark(src.get_flag() ) ) {
      localTempMap_.clear();
    }
  }
}

void Propagate::search_propagate_init(const Node& src,
                                      const uint8_t pos,
                                      unordered_set<Node,NodeHash>& prpgt_res)
{
  uint32_t idx  = src.get_index();
  Record rec    = log_.get_record(idx);

  Node dst      = rec.get_const_dst_node();
  char taint_pos = (1 << pos);

  if(src.is_src() ) {
    handle_destinate_node(dst, taint_pos, false, prpgt_res);
  }else {
    string flag = dst.get_flag();
    if(is_store(flag) ) {
      handle_destinate_node(dst, taint_pos, true, prpgt_res);
    }else {
      cout << "search propagation: given source is not a memory..." << endl;
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
  } else if(is_global_temp(addr) ) {
    is_valid_prpgt  = handle_source_node_gl(node, taint_pos);
  } else {
    is_valid_prpgt  = handle_source_node_ll(node, taint_pos);
  }

  return is_valid_prpgt;
}


bool Propagate::handle_source_node_mem(Node &node, char &taint_pos)
{
  string addr       = node.get_addr();
  uint32_t byte_sz  = node.get_sz_byte();
  string val        = node.get_val();

  vector<MemVal_> v_mem_val;
  split_memory(addr, byte_sz, val, v_mem_val);
//  for(auto it = v_mem_val.begin(); it != v_mem_val.end(); ++it) {
//    it->print_mem_val();
//  }

  uint32_t idx_byte = 0;
  for(auto it = v_mem_val.begin(); it != v_mem_val.end(); ++it) {
    string byte_addr  = it->addr;
    // should use dec instead of hex
    uint32_t int_addr = stoul(byte_addr, nullptr, 10);

    // if the byte is tainted
    if(memTaintMap_.isTainted(int_addr)
       && memValMap_.find(int_addr) != memValMap_.end() ) {
      // If value is also matched
      string hash_val   = memValMap_[int_addr];
      string byte_val   = it->val;

      // should be hex instead of dec
      uint32_t i_hash_val   = stoul(hash_val, nullptr, 16);
      uint32_t i_byte_val   = stoul(byte_val, nullptr, 16);

      if(i_hash_val == i_byte_val) {
        // saves taint pos
        taint_pos |= (1 << idx_byte);
      }
    }

    idx_byte++;
  }

  if(taint_pos > 0) { return true; }
  else { return false; }
}


bool Propagate::handle_source_node_gl(Node &node, char &taint_pos)
{
  bool is_match     = false;
  uint32_t int_addr = stoul(node.get_addr(), nullptr, 16);

  if(globalTempMap_.find(int_addr) != globalTempMap_.end() ) {
    taint_pos           = globalTempMap_[int_addr].taint;
    string hash_val     = globalTempMap_[int_addr].val;
    string node_val     = node.get_val();
    is_match            = compr_tmp_val(taint_pos, hash_val, node_val);
  }

  return is_match;
}

bool Propagate::handle_source_node_ll(Node &node, char &taint_pos)
{
  bool is_match     = false;
  uint32_t int_addr = stoul(node.get_addr(), nullptr, 16);

  if(localTempMap_.find(int_addr) != localTempMap_.end() ) {
    taint_pos       = localTempMap_[int_addr].taint;
    string hash_val = localTempMap_[int_addr].val;
    string node_val = node.get_val();
    is_match        = compr_tmp_val(taint_pos, hash_val, node_val);
  }

  return is_match;
}

void Propagate::handle_destinate_node(const Node &node,
                                      char &taint_pos,
                                      bool is_taint_src,
                                      unordered_set<Node, NodeHash> &prpgt_res) {
//  node.print_node();

  string flag = node.get_flag();
  string addr = node.get_addr();
  string val  = node.get_val();

  uint32_t int_addr = 0;

  if(is_store(flag)
     || (is_load(flag) && is_taint_src) ) {
    handle_destinate_node_mem(node, taint_pos, is_taint_src, prpgt_res);
  } else if(is_global_temp(addr) ) {
    int_addr                = stoul(addr, nullptr, 16);
    TempDataType_ tmp_data  = {taint_pos, val};

    if(globalTempMap_.find(int_addr) != globalTempMap_.end() ) {
      // If already exists
      globalTempMap_.erase(int_addr);
      globalTempMap_[int_addr]  = tmp_data;
    } else {
      globalTempMap_[int_addr]  = tmp_data;
    }
  } else {
    int_addr                = stoul(addr, nullptr, 16);
    TempDataType_ tmp_data  = {taint_pos, val};

    if(localTempMap_.find(int_addr) != localTempMap_.end() ) {
      localTempMap_.erase(int_addr);
      localTempMap_[int_addr] = tmp_data;
    } else {
      localTempMap_[int_addr] = tmp_data;
    }
  }
}

void Propagate::handle_destinate_node_mem(const Node &node,
                                          char &taint_pos,
                                          bool is_taint_src,
                                          unordered_set<Node,NodeHash> &prpgt_res)
{
  string node_addr = node.get_addr();
  string node_val  = node.get_val();
  uint32_t int_node_addr  = node.get_int_addr();
  uint32_t mem_byte_sz    = node.get_sz_byte();

  if(is_taint_src) {
    handle_destinate_node_src(node, taint_pos);
  }else {
    // Reference CipherXray's code ByteTaintAnalysis.cpp:342
    // add taint memory bitmap
    uint32_t len        = 0;
    uint32_t byte_addr  = int_node_addr;

    for(uint32_t idx_byte = 0; idx_byte < mem_byte_sz; idx_byte++) {
      if( (taint_pos >> idx_byte) & 0x1) {
        len++;
      } else {
        if(len != 0) {
          memTaintMap_.mark(byte_addr, len);
        }

        // correct?
        byte_addr += len + 1;
        len = 0;
      }
    }

    // handles last
    if(len != 0) {
      memTaintMap_.mark(byte_addr, len);
    }

    // adds (updates) memory value map
    vector<MemVal_> v_mem_val;
    split_memory(node_addr, mem_byte_sz, node_val, v_mem_val);

    for(uint32_t idx_byte = 0; idx_byte < mem_byte_sz; idx_byte++) {
      uint32_t i_byte_addr  = stoul(v_mem_val[idx_byte].addr, nullptr, 10);
      string byte_val       = v_mem_val[idx_byte].val;

      if(memValMap_.find(i_byte_addr) != memValMap_.end() ) {
        memValMap_.erase(i_byte_addr);
        memValMap_[i_byte_addr] = byte_val;
      }else {
        memValMap_[i_byte_addr] = byte_val;
      }

      // inserts to propagate result
//      cout << "propagate to: " << hex << i_byte_addr
//           << " val: " << byte_val << endl;
      Node res;
      to_one_byte_node(node.get_flag(), i_byte_addr, byte_val, res);
      add_prpgt_res(res, prpgt_res);
    }
  }
}

void Propagate::handle_destinate_node_src(const Node& node, char& taint_pos)
{
  string node_addr = node.get_addr();
  string node_val  = node.get_val();
  uint32_t int_node_addr  = node.get_int_addr();
  uint32_t mem_byte_sz    = node.get_sz_byte();

  // Need to split into <byte, val>, then store to memory value hashmap
  vector<MemVal_> v_mem_val;
  split_memory(node_addr, mem_byte_sz, node_val, v_mem_val);

  for(uint32_t idx_byte = 0; idx_byte < mem_byte_sz; idx_byte++) {
    if( (taint_pos >> idx_byte) & 0x1) {
      uint32_t byte_addr  = int_node_addr + idx_byte;
      string byte_val     = v_mem_val[idx_byte].val;

      memTaintMap_.mark(byte_addr, 1);
      memValMap_[byte_addr] = byte_val;
    }
  }
}

void Propagate::split_memory(const std::string addr,
                             const uint32_t byte_sz,
                             const std::string val,
                             std::vector<MemVal_>& split_res)
{
  MemVal_ mem_val;

  uint32_t int_addr   = stoul(addr, nullptr, 16);
  uint32_t idx_byte   = 0;

  string byte_val       = val;
  uint8_t byte_val_len  = byte_val.length();

  for(; idx_byte < byte_sz; idx_byte++) {
    string byte_addr    = to_string(int_addr+idx_byte);
    mem_val.addr        = byte_addr;

    if(byte_val_len == 0) {
      mem_val.val   = "0";
    } else if(byte_val_len > 0
              && byte_val_len <= xt_const::BYTE_VAL_STR_LEN) {
      mem_val.val   = byte_val;
    } else {
      mem_val.val   = byte_val.substr(byte_val_len - xt_const::BYTE_VAL_STR_LEN,
                                      xt_const::BYTE_VAL_STR_LEN);
    }

    split_res.push_back(mem_val);

    // removes byte val has been processed
    if(byte_val_len > xt_const::BYTE_VAL_STR_LEN) {
      byte_val  = byte_val.substr(0, byte_val_len-xt_const::BYTE_VAL_STR_LEN);
      byte_val_len  = byte_val.length();
    } else {
      byte_val  = "0";
    }
  }
}

// Fixed bug: af5ab301 and af5ab302 returns true
bool Propagate::compr_tmp_val(char &taint_pos,
                              std::string hash_val,
                              std::string node_val)
{
  bool is_match   = false;

  // max is 4 bytes
  for(uint32_t idx_byte = 0; idx_byte < 4; idx_byte++) {
    // checks if corresponding byte is tainted, via:
    // last bit of taint_pos is 1
    if( (taint_pos >> idx_byte) & 0x1 ) {
      string val_hash_byte  = get_last_byte(hash_val);
      string val_node_byte  = get_last_byte(node_val);

      uint32_t i_hash_val   = stoul(val_hash_byte, nullptr, 16);
      uint32_t i_node_val   = stoul(val_node_byte, nullptr, 16);

      if(i_hash_val == i_node_val) {
        is_match = true;
      } else {
        return false;
      }
    }

    // removes last two bytes that had been processed
    uint32_t hash_val_len = hash_val.length();
    if(hash_val_len > xt_const::BYTE_VAL_STR_LEN) {
      hash_val  = hash_val.substr(0, hash_val_len - xt_const::BYTE_VAL_STR_LEN);
    } else {
      hash_val  = "0";
    }

    uint32_t node_val_len = node_val.length();
    if(node_val_len > xt_const::BYTE_VAL_STR_LEN) {
      node_val  = node_val.substr(0, node_val_len - xt_const::BYTE_VAL_STR_LEN);
    } else {
      node_val  = "0";
    }

  }

  return is_match;
}

std::string Propagate::get_last_byte(const std::string& val)
{
  uint32_t val_len    = val.length();
  if(val_len == 0) { return "0"; }
  else if(val_len > 0 && val_len <= 2) { return val; }
  else {
    return val.substr(val_len - xt_const::BYTE_VAL_STR_LEN,
                      xt_const::BYTE_VAL_STR_LEN);
  }
}

void Propagate::to_one_byte_node(const string& flag,
                                 uint32_t byte_addr,
                                 const string& val,
                                 Node &node_res)
{
  node_res.set_flag(flag);
  node_res.set_addr(to_string(byte_addr) );
  node_res.set_val(val);

  node_res.set_int_addr(byte_addr);
  node_res.set_sz_byte(1);
}

void Propagate::add_prpgt_res(const Node& node,
                              unordered_set<Node,NodeHash>& prpgt_res)
{
  unordered_set<Node,NodeHash>::const_iterator got = prpgt_res.find(node);
  if(got == prpgt_res.end() ) {
    prpgt_res.insert(node);
  }
}

bool Propagate::is_insn_mark(const std::string& flag)
{
  if(util::equal_mark(flag, flag::XT_INSN_ADDR) ) { return true; }
  else { return false; }
}

bool Propagate::is_bitwise_ir(const std::string& flag)
{
  for(auto it = bitwise_ir_filter.begin(); it != bitwise_ir_filter.end(); ++it) {
    if(flag.compare(*it) == 0) {
      return true;
    }
  }

  return false;
}

bool Propagate::is_load(const std::string& flag)
{
  if(util::equal_mark(flag, flag::TCG_QEMU_LD) ) { return true; }
  else { return false; }
}

bool Propagate::is_store(const std::string& flag)
{
  if(util::equal_mark(flag, flag::TCG_QEMU_ST)
     || util::equal_mark(flag, flag::TCG_QEMU_ST_POINTER) ) {
    return true;
  } else { return false; }
}

bool Propagate::is_global_temp(const std::string& addr)
{
  uint32_t int_addr   = stoul(addr, nullptr, 16);
  switch(int_addr) {
    case flag::G_TEMP_UNKNOWN:
    case flag::G_TEMP_ENV:
    case flag::G_TEMP_CC_OP:
    case flag::G_TEMP_CC_SRC:
    case flag::G_TEMP_CC_DST:
    case flag::G_TEMP_CC_TMP:
    case flag::G_TEMP_EAX:
    case flag::G_TEMP_ECX:
    case flag::G_TEMP_EDX:
    case flag::G_TEMP_EBX:
    case flag::G_TEMP_ESP:
    case flag::G_TEMP_EBP:
    case flag::G_TEMP_ESI:
    case flag::G_TEMP_EDI:
      return true;
  }
  return false;
}
