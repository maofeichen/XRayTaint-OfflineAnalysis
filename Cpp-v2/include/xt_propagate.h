#ifndef XT_PROPAGATE_H_
#define XT_PROPAGATE_H_ 

// This class mostly implements the taint source propagation search.
// Given a taint source and a xray taint log, searches all the memories
// that the taint source can propagate to. 

#include "xt_log.h"
#include "xt_data.h"
#include "TaintBitMap.h"

#include <google/dense_hash_map>
#include <string>
#include <unordered_set>
#include <vector>

// Stores the propagate results in a hashmap 
struct PropagateRes
{
    NodePropagate src;
    std::unordered_set<Node, NodeHash> propagateRes;
};

// The hash function used in the hashmap of proagate results.
// The hash key is position (index) of the taint source in the log.
struct PropagateResHash 
{
    std::size_t operator()(const PropagateRes &propagateRes) const {
        size_t h1 ( std::hash<int>()(propagateRes.src.pos) );
        return h1;
    }
};

inline bool operator==(PropagateRes const& p1, PropagateRes const& p2){
    return p1.src.pos == p2.src.pos && p1.src.isSrc == p2.src.isSrc;
}

// store <mem, val> info in byte level
struct MemVal_
{
    std::string addr;
    std::string val;
};

class Propagate
{
public:
    Propagate();
    Propagate(XTLog &xtLog);

    // Stores all propagation results that had been searched before.
    // Improves the performance likes a cache.
    std::unordered_set<PropagateRes, PropagateResHash> setOfPropagateRes;

    // A wrapper function to get the propagate result.
    // Returns the taint source propagation results.
    //
    // Before the search, it first checks if the taint source had been
    // searched before (already in a hashset).
    //      If yes, returns results from hashset; 
    //      else search propagation.
    std::unordered_set<Node, NodeHash> getPropagateResult(NodePropagate &s, 
                                                          std::vector<Record> &vRec);

    // INGORE!!!
    // std::unordered_set<Node, NodeHash> searchAvalanche(std::vector<std::string> &log, 
    //                                                    std::vector<NodePropagate> &allPropgateRes);
private:
    // a maximum byte value in string, its max len 
    const unsigned int BYTE_VAL_STR_LEN = 2;

    // new class to store xray taint log 
    XTLog m_xtLog;

    // <taint, val> info, uses as data type of temp hashmap
    struct tempDataType_
    {
       char taint;
       string val; 
    };
    // hashmap for local temps of Qemu, e.g. index as 0, 1, 2...
    google::dense_hash_map<int, tempDataType_> localTempMap_;
    // hashmap for global temps of Qemu, encodes as 0xfff0, 0xfff1...
    google::dense_hash_map<int, tempDataType_> globalTempMap_;

    // Memory taint bitmap to store <memory, taint> info as it is 
    // propagated by the taint source
    TaintBitMap memTaintMap_;
    // Since XinLi's TaintBitMap doesn't store the value of a memory,
    // but we need it during the propagate search .
    // Thus use another hashmap to store <mem, val> infomation, in byte level
    google::dense_hash_map<unsigned int, string> memValMap_;

    inline std::string getInsnAddr(unsigned int &idx, std::vector<Record> &v_rec);
    inline NodePropagate propagate_dst(NodePropagate &s, std::vector<Record> &r);
    inline NodePropagate propagte_src(NodePropagate &d, std::vector<Record> &v_rec, int i);
    inline void insert_propagate_result(Node &n, std::unordered_set<Node, NodeHash> &res);
    inline bool is_valid_propagate(NodePropagate &currNode, Record &currRec, std::vector<Record> &v_rec);
    inline bool is_save_to_q_propagate(bool isSameInsn, int &numHit);

    static bool compare_buffer_node(const NodePropagate &a, const NodePropagate &b);
    void insert_buffer_node(NodePropagate &node, std::vector<NodePropagate> &v_propagate_buf, int &numHit);

    // Splits a multiple byte memory into byte level,
    // Returns a vector of <mem, val>
    // Assumes the byte, val is in Little_endian
    std::vector<MemVal_> split_mem(std::string addr,
                                   unsigned int byteSz,
                                   std::string val);
    // Converts a memory XTNode to a Node
    inline void convert_mem_xtnode(XTNode &xtNode, Node &node);
    // Returns true if a given addr is global temporary
    inline bool is_global_temp(std::string &addr);
    // Returns ture if the record is a memory load operation
    inline bool is_mem_load(std::string &addr);
    // Returns ture if the record is a memory store operation
    inline bool is_mem_stroe(std::string &addr);

    // Returns the taint source propagation search results.
    // Uses breath first search (bfs), slow in performance.
    std::unordered_set<Node, NodeHash> bfs_old(NodePropagate &s, 
                                               std::vector<Record> &v_rec);

    // Returns the taint srouce propagate search results.
    // References CipherXray's Code and uses a new search algorithm.
    // The complexity is O(n), n is the size of xray taint log.
    std::unordered_set<Node, NodeHash> search_propagate(NodePropagate &taint_src);

    // Handles source node if its addr is a memory
    // Returns true if any byte of the memory:
    //  1) is tainted, and
    //  2) its value is matched with the one stored in hash
    //
    // Also stores the taint info (which byte is tainted) int var: taint
    bool handle_source_node_mem(XTNode &node, char &taint);

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
    bool handle_source_node(XTNode &node);

    // Handles the destinatin node during the search of propagation.
    // Specifically, analyzes if the node address is:
    //  1. memory address
    //  2. local temporary index
    //  3. global temporary indxe
    // and its size.
    //
    // Then assigns it if:
    //  1) -> memory taint bitmap and propagate result
    //  2) -> local temp map
    //  3) -> global temp map  
    void handle_destinate_node(XTNode &xtNode, 
                               std::unordered_set<Node, NodeHash> &propagate_res); 

    // IGNORE!!! 
    // std::vector<Record> initRec(std::vector<std::string> &log); 

    // Move to preprocess
    // inline RegularRecord initMarkRecord(std::vector<std::string> &singleRec);      
    // inline RegularRecord initRegularRecord(std::vector<std::string> &singleRec);   

    // std::unordered_set<Node, NodeHash> bfs(NodePropagate &s, std::vector<Record> &r);
    // std::unordered_set<Node, NodeHash> bfs_old_debug(NodePropagate &s, 
    //                                                  std::vector<Record> &v_rec, 
    //                                                  std::vector<NodePropagate> &allPropgateRes);

};
#endif
