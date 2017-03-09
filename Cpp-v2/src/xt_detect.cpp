#include "xt_blockdetect.h"
#include "xt_ByteTaintPropagate.h"
#include "xt_detect.h"
#include "xt_flag.h"
#include "xt_util.h"

#include <algorithm>
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

void Detect::detect_cipher()
{
    cout << "Detecting cipher after liveness analysis..." << endl;

    Propagate propagate(xt_log_);

    // vector<t_AliveFunctionCall>::iterator it_in_func = v_func_cont_buf_.end() - 2;
     vector<t_AliveFunctionCall>::iterator it_in_func = v_func_cont_buf_.begin() + 3;

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

                        // detect_cipher_in_out(in_buf, out_buf, propagate);

                        // Debug
                        if(in_buf.beginAddress == 0xbffff70c){
                            cout << "function call mark:" << it_in_func->call_mark << endl;
                            vector<unsigned long>::const_iterator it_n_idx = it_in_buf->vNodeIndex.begin();
                            for(; it_n_idx != it_in_buf->vNodeIndex.end(); ++it_n_idx){
                                cout << "src index: " << *it_n_idx << endl;
                            }
                            if(it_in_func->call_mark == "14 bffff48c    8048a04 107662"){
                                vector<unsigned long>::const_iterator it_n_idx = it_in_buf->vNodeIndex.begin();
                                for(; it_n_idx != it_in_buf->vNodeIndex.end(); ++it_n_idx){
                                    cout << "src index: " << *it_n_idx << endl;
                                }
                            }
                            detect_cipher_in_out(in_buf, out_buf, propagate);
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

unordered_set<Node, NodeHash>
Detect::comp_multi_src_propagate_res(unsigned int multi_src_interval,
                                     vector<unsigned long>::const_iterator it_multi_src_idx,
                                     unsigned int byte_pos,
                                     Propagate &propagate)
{

    unordered_set<Node, NodeHash> propagate_res;
    unordered_set<Node, NodeHash> multi_propagate_res;

    for(int i = 0; i < multi_src_interval; i++){
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

    unordered_set<Node,NodeHash>::const_iterator it_multi;

    it_multi = multi_propagate_res.begin();
    // Only needs addr and val, size is 1 byte by default
    for(; it_multi != multi_propagate_res.end(); ++it_multi){
        propagate_byte.addr = (*it_multi).i_addr;
        propagate_byte.val  = (*it_multi).val;
        v_propagate_byte.push_back(propagate_byte);
    }

    return v_propagate_byte;
}

vector< vector<Detect::propagate_byte_> >
Detect::gen_in_propagate_byte(t_AliveContinueBuffer &in, Propagate &propagate)
{
    vector< vector<propagate_byte_> > in_vec_propagate_byte;

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
        if(byte_pos > 3){
            byte_pos = 0;
            it_node_idx += multi_src_interval;
        }
    }

    return in_vec_propagate_byte;
}

void Detect::gen_byte_range_array(vector<Detect::propagate_byte_> v_propagate_byte,
                                  RangeArray *range_array)
{
    sort(v_propagate_byte.begin(), v_propagate_byte.end() );

    vector<propagate_byte_>::const_iterator it_propagate_byte;
    it_propagate_byte = v_propagate_byte.begin();

    unsigned long range_begin_addr = (*it_propagate_byte).addr;
    unsigned int range_len = 1;

    for(; it_propagate_byte != v_propagate_byte.end(); ++it_propagate_byte){
        unsigned long curr_begin_addr = (*it_propagate_byte).addr;

        if(range_begin_addr + range_len == curr_begin_addr){
            range_len++;
        }
        else if(range_begin_addr + range_len < curr_begin_addr){
            // cout << "a new range, previous range: " <<
            //         "addr: " << hex << range_begin_addr <<
            //         " len: " << dec << range_len << " bytes" << endl;

            range_array->add_range(range_begin_addr, range_len);
            // range_array.add_range(range_begin_addr, range_len);

            // Init for next range
            range_begin_addr = curr_begin_addr;
            range_len = 1;
        }
    }

    // range_array.disp_range_array();
}

void Detect::gen_in_range_array(t_AliveContinueBuffer &in,
	                            vector< vector<Detect::propagate_byte_> > &in_vec_propagate_byte,
	                            vector<ByteTaintPropagate *> &in_taint_propagate)
{
    // vector<RangeArray *> v_range_array;

    unsigned long begin_addr = in.beginAddress;
    vector< vector<propagate_byte_> >::const_iterator it_in_byte;

    it_in_byte = in_vec_propagate_byte.begin();
    for(; it_in_byte != in_vec_propagate_byte.end(); ++it_in_byte){
        // RangeArray *range_array = new RangeArray();
        // gen_byte_range_array(*it_in_byte, range_array);
        // range_array->disp_range_array();

        // v_range_array.push_back(range_array);

        ByteTaintPropagate *byte_taint_propagate =
                new ByteTaintPropagate(begin_addr);
        gen_byte_range_array(*it_in_byte, byte_taint_propagate->get_taint_propagate() );
        // byte_taint_propagate->get_taint_propagate()->disp_range_array();

        in_taint_propagate.push_back(byte_taint_propagate);

        begin_addr++;
    }

    // for(int i = 0; i < in_taint_propagate.size(); i++){
    //     in_taint_propagate[i]->get_taint_propagate()->disp_range_array();
    // }
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
	                              t_AliveContinueBuffer &out,
	                              Propagate &propagate)
{
    vector< vector<propagate_byte_> > in_vec_propagate_byte;
    in_vec_propagate_byte = gen_in_propagate_byte(in, propagate);
    cout << "numbef of bytes in in buffer: " << dec << in.size / 8 << endl;
    cout << "number of vector of propagte bytes: " << dec << in_vec_propagate_byte.size() << endl;

    vector<ByteTaintPropagate *> in_taint_propagate;
    gen_in_range_array(in, in_vec_propagate_byte, in_taint_propagate);

    for(int i = 0; i < in_taint_propagate.size(); i++){
        cout << "taint src: " << hex << in_taint_propagate[i]->get_taint_src() << endl;
        in_taint_propagate[i]->get_taint_propagate()->disp_range_array();
    }


    Blocks blocks;

    BlockDetect block_detect;
    // block_detect.detect_block_size(blocks, in_taint_propagate, in.size / 8,
    //                                out.beginAddress, out.size / 8);
    block_detect.detect_block_size_alter(blocks, in_taint_propagate, in.size / 8,
                                         out.beginAddress, out.size / 8);

    if(blocks.size() == 0){
        cout << "No block identified" << endl;
        return;
    }
}
