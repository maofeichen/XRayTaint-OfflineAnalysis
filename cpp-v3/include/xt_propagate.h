#ifndef XT_PROPAGATE_H
#define XT_PROPAGATE_H

#include "xt_log.h"
#include "TaintBitMap.h"

#include <google/dense_hash_map>
#include <iostream>
#include <string>
#include <unordered_set>

// store <mem, val> info in byte level
struct MemVal_
{
    std::string addr;
    std::string val;
    void print_mem_val() {
      std::cout << "mem val: " << std::endl;
      std::cout << "addr: "    << addr << std::endl;
      std::cout << "val: "     << val  << std::endl;
    }
};

class Propagate{
public:
  Propagate(const Log& log) : log_(log)
  {
    localTempMap_.set_empty_key((unsigned int) - 1);
    localTempMap_.set_deleted_key(0xfffffffe);

    globalTempMap_.set_empty_key((unsigned int) - 1);
    globalTempMap_.set_deleted_key(0xfffffffe);

    memValMap_.set_empty_key((unsigned int) - 1);
    memValMap_.set_deleted_key(0xfffffffe);
  }

  void get_taint_prpgt(const Node& src,
                       const uint8_t pos,
                       std::unordered_set<Node,NodeHash>& prpgt_res);
private:
  const Log& log_;

  // <taint, val> info, uses as data type of temp hashmap
  struct TempDataType_
  {
     char taint;
     std::string val;
  };

  // hashmap for local temps of Qemu, e.g. index as 0, 1, 2...
  google::dense_hash_map<uint32_t, TempDataType_> localTempMap_;

  // hashmap for global temps of Qemu, encodes as 0xfff0, 0xfff1...
  google::dense_hash_map<uint32_t, TempDataType_> globalTempMap_;

  // Memory taint bitmap to store <memory, taint> info as it is
  // propagated by the taint source
  TaintBitMap memTaintMap_;

  // Since XinLi's TaintBitMap doesn't store the value of a memory,
  // but we need it during the propagate search .
  // Thus use another hashmap to store <mem, val> infomation, in byte level
  google::dense_hash_map<uint32_t, std::string> memValMap_;

  // IR bitwise operation filter
  const std::vector<std::string> bitwise_ir_filter = {
    "52", // TCG_QEMU_LOAD
    "5a", // TCG_QEMU_STORE
    "51", // TCG_QEMU_MOV
    "46", // TCG_QEMU_OR
    "47", // TCG_QEMU_XOR
  };

  void search_propagate(const Node& src,
                        const uint8_t pos,
                        std::unordered_set<Node,NodeHash>& prpgt_res);

  void search_propagate_init(const Node& src,
                             const uint8_t pos,
                             std::unordered_set<Node,NodeHash>& prpgt_res);

  // Handles source node during propagation search.
  // Returns true if the source node is a valid propagate node
  // from node stored in either:
  //  * TaintBitMap (memory)
  //  * loadl temp map
  //  * global temp map
  //
  // Generally, a valid propagation:
  //  1) is tainted (stored in temp map or bitmap), and
  //  2) value is matched
  bool handle_source_node(Node &node, char &taint_pos);

  // Handles source node if its addr is a memory
  // Returns true if any byte of the memory:
  //  1) is tainted, and
  //  2) its value is matched with the one stored in hash
  //
  // Also stores the taint info (which byte is tainted) int var: taint
  bool handle_source_node_mem(Node &node, char &taint_pos);

  // Handles source node if it's a global temp
  // Returns true and the taint info, if:
  //  1) it is tainted
  //  2) any value of tainted byte is same in the hashmap
  //      is same as the current value
  bool handle_source_node_gl(Node &node, char &taint_pos);

  // Handles source node if it's a local temp
  // Returns true and the taint info, if:
  //  1) it is tainted
  //  2) any value of tainted byte is same in the hashmap
  //      is same as the current value
  bool handle_source_node_ll(Node &node, char &taint_pos);

  // Handles the destination node during the search of propagation.
  // Specifically, analyzes if the node address is:
  //  1. memory address
  //  2. local temporary index
  //  3. global temporary indxe
  // and its taint size.
  //
  // Memory:
  //  based on the taint info (indicating which byte is tainted),
  //      1) mark the coressponding byte tainted in the taint bit map and
  //      2) add (update) the corresponding byte in the memory val hash map
  //      3) If the memory is NOT taint source, also add it to the propagate result
  //
  //  local temp:
  //      add (update) the local temp in local temp hashamp
  //  global temp:
  //      add (update) the global temp in global temp hashamp
  void handle_destinate_node(const Node &node,
                             char &taint_pos,
                             bool is_taint_src,
                             std::unordered_set<Node, NodeHash> &prpgt_res);

  // Handles the destination memory node
  void handle_destinate_node_mem(const Node& node,
                                 char &taint_pos,
                                 bool is_taint_src,
                                 std::unordered_set<Node,NodeHash> &prpgt_res);

  void handle_destinate_node_src(const Node& node, char& taint_pos);

  // Splits a multiple byte memory into byte level,
  // Returns a vector of <mem, val>
  // Assumes the byte, val is in Little_endian
  void split_memory(const std::string addr,
                    const uint32_t byte_sz,
                    const std::string val,
                    std::vector<MemVal_>& split_res);
  // Compares the temp's stored value (hashval) and current value (nodeVale)
  // given a taint bitmap indicating the corresponding position of each
  // byte that need to compare
  // Returns true if all positions are same value
  bool compr_tmp_val(char &taint_pos,
                     std::string hash_val,
                     std::string node_val);
  // Returns a string last 2 bytes' value
  // Semantically the string stores a 4 bytes value, it returns the last byte val
  std::string get_last_byte(const std::string& val);

  void to_one_byte_node(const std::string& flag,
                        uint32_t byte_addr,
                        const std::string& val,
                        Node &node_res);

  void add_prpgt_res(const Node& node,
                     std::unordered_set<Node,NodeHash>& prpgt_res);

  bool is_insn_mark(const std::string& flag);
  bool is_bitwise_ir(const std::string& flag);
  bool is_load(const std::string& flag);
  bool is_store(const std::string& flag);
  bool is_global_temp(const std::string& addr);
};
#endif
