#include "xt_detect.h"
#include "xt_flag.h"
#include "xt_util.h"

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
    propagate_ = Propagate(xt_log_);
}

void Detect::detect_cipher()
{
    cout << "Detecting cipher after liveness analysis..." << endl;

    vector<t_AliveFunctionCall>::iterator it_in_func = v_func_cont_buf_.end() - 2;
    // vector<t_AliveFunctionCall>::iterator itInFunction = v_func_cont_buf_.begin();

    // Iterates each function call
    for(; it_in_func != v_func_cont_buf_.end() - 1; ++it_in_func){
        vector<t_AliveFunctionCall>::const_iterator it_out_func = it_in_func + 1;

        for(; it_out_func != v_func_cont_buf_.end(); ++it_out_func){
            // Iterates each continuous buffer in each function call
            vector<t_AliveContinueBuffer> v_in_buf = (*it_in_func).vAliveContinueBuffer;
            vector<t_AliveContinueBuffer>::const_iterator it_in_buf = v_in_buf.begin();

            for(; it_in_buf != v_in_buf.end(); ++it_in_buf){
                vector<t_AliveContinueBuffer> v_out_buf = (*it_out_func).vAliveContinueBuffer;
                vector<t_AliveContinueBuffer>::const_iterator it_out_buf = v_out_buf.begin();

                for(; it_out_buf != v_out_buf.end(); ++it_out_buf){
                    if( (*it_in_buf).beginAddress != (*it_out_buf).beginAddress){
                        t_AliveContinueBuffer in_buf = *it_in_buf;
                        t_AliveContinueBuffer out_buf = *it_out_buf;
                        detect_cipher_in_out(in_buf, out_buf);
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
    unsigned long count = 0;

    XTNode node = get_mem_node(*it_node_idx);
    unsigned long begin_addr = node.getIntAddr();

    for(;
        it_node_idx != v_node_idx.end() && begin_addr == node.getIntAddr();
        ++it_node_idx){

        count++;
        node = get_mem_node(*it_node_idx);
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
    unordered_set<Node, NodeHash>::const_iterator it_propagate_res =
            propagate_res.begin();
    for(; it_propagate_res != propagate_res.end(); ++it_propagate_res){
        unordered_set<Node, NodeHash>::const_iterator got_multi =
                multi_propagate_res.find(*it_propagate_res);
        if( got_multi != multi_propagate_res.end() ){
            multi_propagate_res.insert(*it_propagate_res);
        }
    }
}

unordered_set<Node, NodeHash>
Detect::comp_multi_src_propagate_res(unsigned int multi_src_interval,
                                     vector<unsigned long>::const_iterator it_multi_src_idx,
                                     unsigned int byte_pos)
{

    unordered_set<Node, NodeHash> propagate_res;
    unordered_set<Node, NodeHash> multi_propagate_res;

    int i = 0;
    for(; i < multi_src_interval - 1; i++){
        XTNode node = get_mem_node(*it_multi_src_idx);
        NodePropagate taint_src = init_taint_source(node, log_rec_);
        propagate_res = propagate_.getPropagateResult(taint_src, log_rec_, byte_pos);
        merge_propagate_res(propagate_res, multi_propagate_res);

        it_multi_src_idx++;
    }

    return multi_propagate_res;
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

void Detect::detect_cipher_in_out(t_AliveContinueBuffer &in,
	                              t_AliveContinueBuffer &out)
{
    unsigned int byte_pos = 0;

    vector<unsigned long>::const_iterator it_node_idx = in.vNodeIndex.begin();

    while(it_node_idx != in.vNodeIndex.end() ){
        unsigned int multi_src_interval =
                comp_multi_src_interval(in.vNodeIndex, it_node_idx);
        vector<unsigned long>::const_iterator it_multi_srcidx = it_node_idx;

        unordered_set<Node, NodeHash> multi_propagate_res =
                comp_multi_src_propagate_res(multi_src_interval, it_multi_srcidx, byte_pos);
    }
}
