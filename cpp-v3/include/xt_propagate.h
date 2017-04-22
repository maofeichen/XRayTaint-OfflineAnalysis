#ifndef XT_PROPAGATE_H
#define XT_PROPAGATE_H

#include "xt_log.h"
#include "TaintBitMap.h"

#include <google/dense_hash_map>
#include <string>
#include <unordered_set>

class Propagate{
public:
  Propagate(const Log& log) : log_(log) {}

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
  google::dense_hash_map<unsigned int, std::string> memValMap_;

  void search_propagate(const Node& src,
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

  bool is_insn_mark(const std::string& flag);
  bool is_load(const std::string& flag);
};
#endif
