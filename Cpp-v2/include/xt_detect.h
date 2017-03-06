// This class is used to detect blocks, modes after liveness
// analysis.

#ifndef XT_DETECT_H_
#define XT_DETECT_H_

#include "xt_propagate.h"
#include "xt_log.h"

#include <unordered_set>
#include <vector>

class Detect{
public:
    Detect(std::vector<t_AliveFunctionCall> v_func_cont_buf,
		   XTLog &xt_log,
		   std::vector<Record> log_rec);

    void detect_cipher();
private:
    XTLog xt_log_;
	std::vector<t_AliveFunctionCall> v_func_cont_buf_;
	std::vector<Record> log_rec_;
	Propagate propagate_;

	// Due to there might be multiple same taint sources (same addr, different val),
	// computes the interval to next different taint source
	inline unsigned long comp_multi_src_interval(std::vector<unsigned long> &v_node_idx,
											     std::vector<unsigned long>::const_iterator it_node_idx);

	inline std::string get_insn_addr(unsigned long idx, std::vector<Record> &v_rec);
	inline void merge_propagate_res(std::unordered_set<Node, NodeHash> &propagate_res,
	                                std::unordered_set<Node, NodeHash> &multi_propagate_res);

	// Computes propagate results for multiple sources
	std::unordered_set<Node, NodeHash> comp_multi_src_propagate_res(
	        unsigned int multi_src_interval,
	        std::vector<unsigned long>::const_iterator it_multi_src_idx,
	        unsigned int byte_pos);

	// get the memory node (load or store) given the index in the log
	XTNode get_mem_node(unsigned long index);

	// Given a node in log, convert it to NodePropagate format as taint source
	// for taint propagation search
	NodePropagate init_taint_source(XTNode &node, std::vector<Record> &log_rec);

	// Detects cipher between a potential input and output buffers
	void detect_cipher_in_out(t_AliveContinueBuffer &in,
	                          t_AliveContinueBuffer &out);
};

#endif /* XT_DETECT_H_ */
