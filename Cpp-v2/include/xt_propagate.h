#ifndef XT_PROPAGATE_H_
#define XT_PROPAGATE_H_ 

// This class mostly implements the taint source propagation search.
// Given a taint source and a xray taint log, searches all the memories
// that the taint source can propagate to. 

#include "xt_log.h"
#include "xt_data.h"

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

class Propagate
{
public:
    Propagate();
    Propagate(XTLog &xtLog);

    std::unordered_set<PropagateRes, PropagateResHash> setOfPropagateRes;

    // INGORE!!!
    std::unordered_set<Node, NodeHash> searchAvalanche(std::vector<std::string> &log, 
                                                       std::vector<NodePropagate> &allPropgateRes);
    std::unordered_set<Node, NodeHash> getPropagateResult(NodePropagate &s, 
                                                          std::vector<Record> &vRec);
private:
    XTLog m_xtLog;

    inline std::string getInsnAddr(unsigned int &idx, std::vector<Record> &v_rec);
    inline NodePropagate propagate_dst(NodePropagate &s, std::vector<Record> &r);
    inline NodePropagate propagte_src(NodePropagate &d, std::vector<Record> &v_rec, int i);
    inline void insert_propagate_result(Node &n, std::unordered_set<Node, NodeHash> &res);
    inline bool is_valid_propagate(NodePropagate &currNode, Record &currRec, std::vector<Record> &v_rec);
    inline bool is_save_to_q_propagate(bool isSameInsn, int &numHit);

    inline bool is_global_temp(std::string &addr);

    inline RegularRecord initMarkRecord(std::vector<std::string> &singleRec);      // Move to preprocess
    inline RegularRecord initRegularRecord(std::vector<std::string> &singleRec);   // Move to preprocess

    static bool compare_buffer_node(const NodePropagate &a, const NodePropagate &b);
    void insert_buffer_node(NodePropagate &node, std::vector<NodePropagate> &v_propagate_buf, int &numHit);

    std::vector<Record> initRec(std::vector<std::string> &log); // IGNORE!!! 

    std::unordered_set<Node, NodeHash> bfs(NodePropagate &s, std::vector<Record> &r);
    std::unordered_set<Node, NodeHash> bfs_old(NodePropagate &s, 
                                               std::vector<Record> &v_rec);   
    std::unordered_set<Node, NodeHash> bfs_old_debug(NodePropagate &s, 
                                                     std::vector<Record> &v_rec, 
                                                     std::vector<NodePropagate> &allPropgateRes);
};
#endif
