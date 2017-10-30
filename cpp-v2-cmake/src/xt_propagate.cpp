#include "xt_flag.h"
#include "xt_log.h"
#include "xt_propagate.h"
#include "xt_node.h"
#include "xt_util.h"
#include "xt_taintpropagate.h"

#include <algorithm>
#include <cassert>
#include <queue>
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>

#define DEBUG 1

using namespace std;
using google::dense_hash_map;

Propagate::Propagate(){}

Propagate::Propagate(XTLog &xtLog)
{
    m_xtLog = xtLog;
    localTempMap_.set_empty_key((unsigned int) - 1);
    localTempMap_.set_deleted_key(0xfffffffe);

    globalTempMap_.set_empty_key((unsigned int) - 1);
    globalTempMap_.set_deleted_key(0xfffffffe);

    memValMap_.set_empty_key((unsigned int) - 1);
    memValMap_.set_deleted_key(0xfffffffe);
}


unordered_set<Node, NodeHash> 
Propagate::getPropagateResult(NodePropagate &s, 
                              std::vector<Record> &vRec,
                              unsigned int byte_pos)
{
    unordered_set<Node, NodeHash> aPropagateRes;

    PropagateRes p;
    p.src = s;

    unordered_set<PropagateRes, PropagateResHash>::const_iterator got = setOfPropagateRes.find(p);
    if( got == setOfPropagateRes.end() ){
        // aPropagateRes = bfs_old(s, vRec);

        aPropagateRes = search_propagate(s, byte_pos);
        // clean bitmap and hashmap after search
        memTaintMap_.reset();
        localTempMap_.clear();
        globalTempMap_.clear();
        memValMap_.clear(); 

        // temporay disable the hash
        // p.propagateRes = aPropagateRes;
        // setOfPropagateRes.insert(p);
        
        return aPropagateRes;
    } else
        return got->propagateRes;
}


unordered_set<Node, NodeHash> Propagate::bfs_old(NodePropagate &s, vector<Record> &v_rec)
{
    unordered_set<Node, NodeHash> res_buffer;
    vector<NodePropagate> v_propagate_buffer;
    queue<NodePropagate> q_propagate;

    NodePropagate currNode, nextNode;
    struct Record currRec;
    int numHit;
    bool isValidPropagate, isSameInsn;

    // If the start node is a dst node, should push to q_propagate instead 
    // of v_propagate_buffer?
    // Because there is rule below that any node in the v_propagate_buffer
    // should be a src (even if it is memory buffer)
    // v_propagate_buffer.push_back(s);

    if(s.isSrc)
        v_propagate_buffer.push_back(s);
    else{
        v_propagate_buffer.push_back(s);
        q_propagate.push(s);
    }
    while(!v_propagate_buffer.empty() ){
    L_Q_PROPAGATE:
        // non buffer propagation
        while(!q_propagate.empty() ){
            numHit = 0;
            isSameInsn = true;

            currNode = q_propagate.front();

            // if a source node
            if(currNode.isSrc){
                unsigned int i = currNode.pos;
                // can't be a mark
                assert( v_rec[i].isMark == false);
                nextNode = propagate_dst(currNode, v_rec);
                // cout << "next dst: lineNO: " << nextNode.pos << \
                //                 " addr: " << nextNode.n.addr << \
                //                 " val: " << nextNode.n.val << endl;
                q_propagate.push(nextNode);
                numHit++;

                // if it is store to buffer operation, save to propagate buffer result
                Node node = nextNode.n;
                if(XT_Util::equal_mark(node.flag, flag::TCG_QEMU_ST) ){
                    insert_propagate_result(node, res_buffer);
                    cout << "Propagate to: line num: " << i;
                    cout << " addr: " << hex << node.addr << " " << node.sz / 8 << "bytes" << endl; 
                }
            }
            // if a dst node
            // find valid propagation from dst -> src for afterwards records
            else{
                numHit = 0;
                isSameInsn = true;  // assume belongs to same insn at first
                vector<Record>::size_type i = currNode.pos + 1;
                for(; i != v_rec.size(); i++) {
                    isValidPropagate = false;
                    currRec = v_rec[i];

                    // if cross insn boundary
                    if(isSameInsn)
                        if(currRec.isMark && 
                            XT_Util::equal_mark(currRec.regular.src.flag, flag::XT_INSN_ADDR) )
                            isSameInsn = false;

                    if(!currRec.isMark){
                        // Not use!!!
                        // isValidPropagate = is_valid_propagate(currNode, currRec, v_rec);

                        XTNode prevDestination;
                        XTNode nextSource;

                        size_t dstIndex = currNode.pos;
                        size_t srcIndex = i;
                        prevDestination = m_xtLog.getRecord(dstIndex).getDestinationNode();
                        nextSource = m_xtLog.getRecord(srcIndex).getSourceNode();

                        TaintPropagate tp;
                        isValidPropagate = tp.isValidPropagate(prevDestination, nextSource);

                        if(isValidPropagate){
                            nextNode = propagte_src(currNode, v_rec, i);
                            // cout << "next src: lineNO: " << nextNode.pos << \
                            //     " addr: " << nextNode.n.addr << \
                            //     " val: " << nextNode.n.val << endl;
                            // is it a load opreration? If so, then it is a memory buffer
                            if(XT_Util::equal_mark(nextNode.n.flag, flag::TCG_QEMU_LD) ){
                                insert_buffer_node(nextNode, v_propagate_buffer, numHit);

                                // also save to propagate result!!!
                                Node node = nextNode.n;
                                cout << "Propagate to: line num: " << i;
                                cout << " addr: " << hex << node.addr << " " << node.sz / 8 << "bytes" << endl; 
                                insert_propagate_result(node, res_buffer);
                            } else{ // if not a buffer node
                            	// No need to use isSameInsn & numHit
                            	/*
                                if(is_save_to_q_propagate(isSameInsn, numHit) ){
                                    q_propagate.push(nextNode);
                                    numHit++;
                                }
                                */
                                q_propagate.push(nextNode);
								numHit++;
                            }
                        } // end isValidPropagate
                    } // end isMark

                    // if not belong to same instruction and
                    // already have hit, and
                    // not a memory buffer
                    // can break the loop
                    //
                    // No need to use!!!
                    if(!isSameInsn && 
                        numHit >= 1 && 
                        // !is_global_temp(currNode.n.addr) && // Not use this for previous test
                        !XT_Util::equal_mark(currNode.n.flag, flag::TCG_QEMU_ST) )
                            break;
                } // end of for loop
            } // end dst node case
            q_propagate.pop();  
        } // end while q_propagate

        if(!v_propagate_buffer.empty() ){
            currNode = v_propagate_buffer[0];
            v_propagate_buffer.erase(v_propagate_buffer.begin() );

            // memory buffer only contains buffer nodes are as src
            if(currNode.isSrc){
                nextNode = propagate_dst(currNode, v_rec);
                q_propagate.push(nextNode);
                numHit++;
            }
        }

        if(!q_propagate.empty() )
            goto L_Q_PROPAGATE;
    } // end while v_propagate_buffer

    return res_buffer;
} 


unordered_set<Node, NodeHash> Propagate::search_propagate(NodePropagate &taint_src, 
                                                          unsigned int byte_pos)
{
    unordered_set<Node, NodeHash> propagate_res;

    unsigned int record_idx = taint_src.pos;
    unsigned int record_size = m_xtLog.getRecordSize();
    XTRecord record = m_xtLog.getRecord(record_idx);
    XTNode src, dst;

    char taint;
    // Processes taint source
    if(taint_src.isSrc){
        src = record.getSourceNode();
        // handle the source as handle destination node
        // it's the initial node: need to store in the *hashmap
        taint = 0;
        // for(unsigned int byteIdx = 0; byteIdx < src.getByteSize(); byteIdx++)
        //     taint |= (1 << byteIdx);

        // use byte_pos to calcuate the taint
        taint = (1 << byte_pos);
        // handle_destinate_node(src, taint, true, propagate_res);

        // handles its destination 
        dst = record.getDestinationNode();
        handle_destinate_node(dst, taint, false, propagate_res);
    }else{
        dst = record.getDestinationNode();
        string flag = dst.getFlag();
        if(is_mem_stroe(flag) ){
            taint = 0;

            // for(unsigned int byteIdx = 0; byteIdx < dst.getByteSize(); byteIdx++){
            //     taint |= (1 << byteIdx);
            // }

            taint = (1 << byte_pos);
            handle_destinate_node(dst, taint, true, propagate_res);
        }else
            cout << "Taint source is not a memory..." << endl;
    }

    // Search taint propagation
    for(record_idx++; record_idx < record_size; record_idx++){
        record = m_xtLog.getRecord(record_idx);
        src = record.getSourceNode();
        dst = record.getDestinationNode();

//        cout << "record: " << record_idx << " src " << src.getAddr() << " val: " << src.getVal() << " dst: " << dst.getAddr() << " val: " << dst.getVal() << endl;

        if(!src.isMark() ){
            // Local temp only use within one instruction. If see source is
            // a global or a memory addr (load), indicates crossing insn
            // boundary.
            // No need to use insn mark.
//            string flag = src.getFlag();
//            string addr = src.getAddr();
//            if(is_mem_load(flag) || is_global_temp(addr) ) {
//                localTempMap_.clear();
//            }

            taint = 0;
            if(handle_source_node(src, taint) ){
//                cout << "record: " << std::dec << record_idx << " src " << src.getAddr() << " val: " << src.getVal() << " dst: " << dst.getAddr() << " val: " << dst.getVal() << endl;


                string flag = src.getFlag();
                // if not bitwise ir, assume all 4 bytes of temp are tainted,
                // results in a overtained to 4 bytes
                if(!is_bitwise_ir(flag) )
                    taint = 15;

                handle_destinate_node(dst, taint, false, propagate_res);

            }
        }else if(is_insn_mark(src.getFlag() ) ){
            // cross insn bounary, clear locam temp
            // local temp can only be used within same instruction (Qemu)
             localTempMap_.clear();
        }
    }

    return propagate_res; 
}

bool Propagate::handle_source_node_local(XTNode &node, char &taint)
{
    bool is_match = false;
    unsigned int intAddr = stoul(node.getAddr(), nullptr, 16);

    if(localTempMap_.find(intAddr) != localTempMap_.end() ){
        taint = localTempMap_[intAddr].taint;
        string hash_val = localTempMap_[intAddr].val; 
        string node_val = node.getVal();
        is_match = compare_temp(taint, hash_val, node_val);
    }
    return is_match;
}

bool Propagate::handle_source_node_global(XTNode &node, char &taint)
{
    bool is_match = false;

    unsigned int intAddr = stoul(node.getAddr(), nullptr, 16);

    if(globalTempMap_.find(intAddr) != globalTempMap_.end() ){
        taint          = globalTempMap_[intAddr].taint;
        string hashVal = globalTempMap_[intAddr].val;
        string nodeVal = node.getVal();
        is_match = compare_temp(taint, hashVal, nodeVal); 
    }
    
    return is_match; 
}

bool Propagate::handle_source_node_mem(XTNode &node, char &taint)
{
    string addr         = node.getAddr();
    unsigned int byteSz = node.getByteSize();
    string val          = node.getVal();

    vector<MemVal_> v_memVal = split_mem(addr, byteSz, val);

    unsigned int byteIdx = 0;
    vector<MemVal_>::const_iterator itByte = v_memVal.begin();
    for(; itByte != v_memVal.end(); ++itByte){
        string byteAddr = (*itByte).addr;
        // should use 10 instead of 16
        unsigned int intAddr = stoul(byteAddr, nullptr, 10);

        // If the byte is tainted
        if(memTaintMap_.isTainted(intAddr) && 
           memValMap_.find(intAddr) != memValMap_.end() ){
            // If value is also match
            string hashVal = memValMap_[intAddr];
            string byteVal = (*itByte).val;

            // should be 16 instead of 10 here
            unsigned int iHashVal = stoul(hashVal, nullptr, 16);
            unsigned int iByteVal = stoul(byteVal, nullptr, 16);

            if(iHashVal == iByteVal)
                taint |= (1 << byteIdx);
        }
        byteIdx++;
    }

    if(taint > 0)
        return true;
    else
        return false;
}

bool Propagate::handle_source_node(XTNode &node, char &taint)
{
    bool is_valid_propagate = false;
    string nodeFlag = node.getFlag();
    string nodeAddr = node.getAddr();

    if(is_mem_load(nodeFlag) ){
        is_valid_propagate = handle_source_node_mem(node, taint);
    }else if(is_global_temp(nodeAddr) ){
        is_valid_propagate = handle_source_node_global(node, taint);
    }else{
        is_valid_propagate = handle_source_node_local(node, taint);
    }

    return is_valid_propagate;
}

void Propagate::handle_destinate_node_mem(XTNode &xt_node,
                                          char &taint, 
                                          bool is_taint_source,
                                          unordered_set<Node,NodeHash> &propagate_res)
{
    string nodeAddr = xt_node.getAddr();
    string nodeVal  = xt_node.getVal();
    unsigned int intNodeAddr = xt_node.getIntAddr();
    unsigned int memByteSz   = xt_node.getByteSize();

    if(is_taint_source){
        // memTaintMap_.mark(intNodeAddr, xt_node.getByteSize() );

        // Need to split into <byte, val>, then store to memory value hashmap
        // memValMap_[intNodeAddr] = nodeVal;
        vector<MemVal_> v_mem_val = split_mem(nodeAddr, memByteSz, nodeVal);

        // vector<MemVal_>::const_iterator it = v_mem_val.begin();
        // for(; it != v_mem_val.end(); ++it){
        //     unsigned int int_byte_addr = stoul(it->addr, nullptr, 10);
        //     string byte_val = it->val;
        //     memValMap_[int_byte_addr] = byte_val;
        // }

        // Only need to store the byte that specify by the taint
        for(unsigned int byteIdx = 0; byteIdx < memByteSz; byteIdx++){
            if((taint >> byteIdx) & 0x1){
                unsigned int i_byte_addr = intNodeAddr+byteIdx;
                memTaintMap_.mark(i_byte_addr, 1);
                string byte_val = v_mem_val[byteIdx].val;
                memValMap_[i_byte_addr] = byte_val;
            }
        }
    }else{
        // Reference CipherXray's code ByteTaintAnalysis.cpp:342
        // add taint memory bitmap
        unsigned int len = 0;
        unsigned int byteAddr = intNodeAddr;
        for(unsigned int byteIdx = 0; byteIdx < memByteSz; byteIdx++){
            if( (taint >> byteIdx) & 0x1){
                len++;
            }else{
                if(len != 0){
                    memTaintMap_.mark(byteAddr, len);
                }

                // correct?
                byteAddr += len + 1;
                len = 0;
            }
        }

        // handle last
        if(len != 0){
            memTaintMap_.mark(byteAddr, len);
        }

        // add(update) memory value map
        vector<MemVal_> v_mem_val = split_mem(nodeAddr, memByteSz, nodeVal);

        for(unsigned int byteIdx = 0; byteIdx < memByteSz; byteIdx++){
            if((taint >> byteIdx) & 0x1){
                // string s_byte_addr = v_mem_val[byteIdx].addr;
                // cout << "byte addr: " << s_byte_addr << endl;
                unsigned int i_byte_addr = stoul(v_mem_val[byteIdx].addr, nullptr, 10);



                string byte_val = v_mem_val[byteIdx].val;

                if(memValMap_.find(i_byte_addr) != memValMap_.end() ){
                    memValMap_.erase(i_byte_addr);
                    memValMap_[i_byte_addr] = byte_val;
                }else
                    memValMap_[i_byte_addr] = byte_val;

                // Inserts to propagate result
                // Inserts based on the taint info, but now insert all
                cout << "propagate to: " << hex << i_byte_addr << " val: " << byte_val << endl;

                // Debug
                if(i_byte_addr == 0xbffff10f) {
                  cout << "propagate to byte: 0xbffff10f" << endl;
                }

                Node node;
                // convert_mem_xtnode(xt_node, node, i_byte_addr);
                convert_to_byte_node(xt_node, node, i_byte_addr, byte_val);
                insert_propagate_result(node, propagate_res);
            }
        }
    }
}

void Propagate::handle_destinate_node(XTNode &xtNode,
                                      char &taint,
                                      bool is_taint_source, 
                                      unordered_set<Node, NodeHash> &propagate_res)
{
    string nodeFlag = xtNode.getFlag();
    string nodeAddr = xtNode.getAddr();
    string nodeVal  = xtNode.getVal();
    unsigned intNodeAddr;

    if(is_mem_stroe(nodeFlag) || 
       (is_mem_load(nodeFlag) && is_taint_source) ){

        handle_destinate_node_mem(xtNode, taint, is_taint_source, propagate_res);

    }else if(is_global_temp(nodeAddr) ){
        intNodeAddr = stoul(nodeAddr, nullptr, 16);
        tempDataType_ temp_data = {taint, nodeVal};

        if(globalTempMap_.find(intNodeAddr) != globalTempMap_.end() ){
            // If already exist
            globalTempMap_.erase(intNodeAddr);
            globalTempMap_[intNodeAddr] = temp_data;
        }else
            globalTempMap_[intNodeAddr] = temp_data;
    }else{
        intNodeAddr = stoul(nodeAddr, nullptr, 16);
        tempDataType_ temp_data = {taint, nodeVal};

        if(localTempMap_.find(intNodeAddr) != localTempMap_.end() ){
            localTempMap_.erase(intNodeAddr);
            localTempMap_[intNodeAddr] = temp_data;
        }else
            localTempMap_[intNodeAddr] = temp_data; 
    }
} 


inline string Propagate::getInsnAddr(unsigned int &idx, vector<Record> &v_rec)
{
   unsigned int i = idx;
   while(i > 0){
       if(v_rec[i].isMark &&
          XT_Util::equal_mark(v_rec[i].regular.src.flag, flag::XT_INSN_ADDR) )
           return v_rec[i].regular.src.addr;
       i--;
   }
   return "";
}


inline NodePropagate Propagate::propagate_dst(NodePropagate &s, vector<Record> &r)
{
    NodePropagate d;
    unsigned int i = s.pos;

    d.isSrc = false;
    d.pos = s.pos;
    d.parentId = s.id;
    d.id = s.id + 1;
    d.layer = s.layer + 1;
    d.insnAddr = getInsnAddr(d.pos, r);

    d.n.flag = r[i].regular.dst.flag;
    d.n.addr = r[i].regular.dst.addr;
    d.n.val = r[i].regular.dst.val;
    d.n.i_addr = r[i].regular.dst.i_addr;
    d.n.sz = r[i].regular.dst.sz;

    return d;
}

inline NodePropagate Propagate::propagte_src(NodePropagate &d, std::vector<Record> &v_rec, int i)
{
    NodePropagate s;

    s.isSrc = true;
    s.pos = i;
    s.parentId = d.id;
    s.id = i * 2;
    s.layer = d.layer + 1;
    s.insnAddr = getInsnAddr(s.pos, v_rec);

    s.n.flag = v_rec[i].regular.src.flag;
    s.n.addr = v_rec[i].regular.src.addr;
    s.n.val = v_rec[i].regular.src.val;
    s.n.i_addr = v_rec[i].regular.src.i_addr;
    s.n.sz = v_rec[i].regular.src.sz;

    return s;
}

inline void Propagate::insert_propagate_result(Node &n, std::unordered_set<Node, NodeHash> &res)
{
    unordered_set<Node, NodeHash>::const_iterator got = res.find(n);
    // if not in the propagate result
    if(got == res.end() )
        res.insert(n);
}

// dst -> src propagation rules:
//      1. records belong to same insn, can have multiple hits
//      2. records beyond insn, can only have one hit
// if the dst node is a store operation, then if
//      dst.addr == current record src.addr
//      consider valid
// else otherwise
//      case 1 - dst.addr == current record src.addr
// Previous rule: ignore!!!
inline bool Propagate::is_valid_propagate(NodePropagate &currNode, 
                                          Record &currRec,
                                          vector<Record> &v_rec)
{
    bool isValidPropagate, isStore; 

    isValidPropagate = false;
    if(XT_Util::equal_mark(currNode.n.flag, flag::TCG_QEMU_ST) )
        isStore = true;
    else
        isStore = false;

    // is the dst node a store operation, indicating node is a memory buffer
    // then only the addresses are same is valid?
    //  1) val are also same
    //  2) if one with large size contains value of another one 
    if(isStore){
        if(currNode.n.addr == currRec.regular.src.addr ){
            if(currNode.n.val == currRec.regular.src.val)
                isValidPropagate = true;
            else if(currNode.n.sz >= currRec.regular.src.sz && 
                    currNode.n.val.find(currRec.regular.src.val) != string::npos)
                isValidPropagate = true;
            // Need the opposite?
        } 
    }else{
        // case 1
        // dst node.addr == current node src.addr
        if(currNode.n.addr == currRec.regular.src.addr){
            // if vals are also same
            if(currNode.n.val == currRec.regular.src.val)
                isValidPropagate = true;
            /*
            else if(currNode.n.val.find(currRec.regular.src.val) != string::npos || 
                        currRec.regular.src.val.find(currNode.n.val) != string::npos)
                isValidPropagate = true;
            // specail case: tcg add
            else if(XT_Util::equal_mark(currRec.regular.src.flag, flag::TCG_ADD) )
                isValidPropagate = true;
            // special case: if current node next node is a tcg xor
            else if(XT_Util::equal_mark(v_rec[currNode.pos + 1].regular.src.flag, flag::TCG_XOR) )
                isValidPropagate = true;
            */
        }
        // case 2
        // load pointer: current node val is same with current record's addr
        // else if(currNode.n.val == currRec.regular.src.addr &&
        //     XT_Util::equal_mark(currNode.n.flag, flag::TCG_QEMU_LD) )
        // No need to equal Qemu Load
        else if(currNode.n.val == currRec.regular.src.addr && currNode.n.val.length() >= 7)
            isValidPropagate = true;
    }

    return isValidPropagate;
}

bool Propagate::compare_buffer_node(const NodePropagate &a, const NodePropagate &b)
{
    return a.id < b.id;
}

void Propagate::insert_buffer_node(NodePropagate &node, 
                                                          vector<NodePropagate> &v_propagate_buf, 
                                                          int &numHit)
{
    bool hasNode = false;
    for(vector<NodePropagate>::iterator it = v_propagate_buf.begin(); 
          it != v_propagate_buf.end(); ++it){
        if((*it).id == node.id)
            hasNode = true;
    }

    if(!hasNode){
        v_propagate_buf.push_back(node);
        sort(v_propagate_buf.begin(), v_propagate_buf.end(), compare_buffer_node);
        numHit++;
    }
}

// determines if it needs to save to the q_propagate given 
//      1). flag of is in same instruction 
//      2). number of valid propagations hits
inline bool Propagate::is_save_to_q_propagate(bool isSameInsn, int &numHit)
{
    bool isSave = false;

    if(isSameInsn)
        isSave = true;
    else{
        if(numHit < 1)
            isSave = true;
    }
    return isSave;
}

inline bool Propagate::is_bitwise_ir(string flag)
{
    vector<string>::const_iterator it = bitwise_ir_filter.begin();
    for(; it != bitwise_ir_filter.end(); ++it){
        if(flag == *(it) )
            return true;
    }
    return false;
}

inline string Propagate::get_string_last_byte(string val)
{
    unsigned int val_len = val.length();
    if(val_len == 0)
        return "0";
    else if(val_len > 0 && val_len <= 2)
        return val;
    else if(val_len > 2)
        return val.substr(val_len-2, 2);
}

// Bug: af5ab301 and af5ab302 return true (fixed)
bool Propagate::compare_temp(char &taint, string hash_val, string node_val)
{
    bool is_match = false;

    // max is 4 bytes
    for(unsigned int byteIdx = 0; byteIdx < 4; byteIdx++){
        // checks last bit (little end) is 1
        if( (taint >> byteIdx) & 0x1){
            string hash_byte_val = get_string_last_byte(hash_val);
            string node_byte_val = get_string_last_byte(node_val);

            unsigned int i_hash_byte = stoul(hash_byte_val, nullptr, 16);
            unsigned int i_node_byte = stoul(node_byte_val, nullptr, 16);

            if(i_hash_byte == i_node_byte)
                is_match = true;
            else{
            	return false;
                // is_match = false;
            }
        }
        // remove the last two bytes' val
        unsigned int hash_val_len = hash_val.length();
        if(hash_val_len > 2)
            hash_val = hash_val.substr(0, hash_val_len - 2);
        else
            hash_val = "0";

        unsigned int node_val_len = node_val.length();
        if(node_val_len > 2)
            node_val = node_val.substr(0, node_val_len - 2);
        else
            node_val = "0";
    }

    return is_match;
}

vector<MemVal_> Propagate::split_mem(string addr,
                                     unsigned int byteSz,
                                     string val)
{
    vector<MemVal_> v_memVal;
    MemVal_ aMemVal;

    unsigned int intAddr = stoul(addr, nullptr, 16);
    unsigned int byteIdx = 0;

    string byteVal          = val;
    unsigned int byteValLen = byteVal.length();

    for(; byteIdx < byteSz; byteIdx++){
        string byteAddr = to_string(intAddr + byteIdx);
        aMemVal.addr = byteAddr;

        if(byteValLen == 0){
            aMemVal.val = "0";
        }else if(byteValLen > 0 && byteValLen <= BYTE_VAL_STR_LEN){
            aMemVal.val = byteVal;
        }else if(byteValLen > BYTE_VAL_STR_LEN){
            aMemVal.val = byteVal.substr(byteValLen - BYTE_VAL_STR_LEN, BYTE_VAL_STR_LEN);
        }

        v_memVal.push_back(aMemVal);

        // remove byte val has been processed
        if(byteValLen > BYTE_VAL_STR_LEN){
            byteVal = byteVal.substr(0, byteValLen - BYTE_VAL_STR_LEN);
            byteValLen = byteVal.length();
        }else{
            byteVal = "0";
            // byteVal.clear();
        }
    }

    return v_memVal;
}

inline void Propagate::convert_mem_xtnode(XTNode &xtNode, Node &node, 
                                          unsigned int i_byte_addr)
{
    node.flag = xtNode.getFlag();
    node.addr = xtNode.getAddr();
    node.val  = xtNode.getVal();
    // node.i_addr = xtNode.getIntAddr();
    node.i_addr = i_byte_addr;
    // bit size? 1 byte
    node.sz     = 8;
    // node.sz     = xtNode.getBitSize();
}

inline void Propagate::convert_to_byte_node(XTNode &xt_node, Node &node,
                                            unsigned int i_byte_addr,
                                            string byte_val)
{
    node.flag = xt_node.getFlag();
    node.addr = to_string(i_byte_addr);
    node.val  = byte_val;
    node.i_addr = i_byte_addr;
    node.sz     = 8; // 1 byte
}

inline bool Propagate::is_global_temp(string &addr) {
  // cout << "addr: " << addr << endl;
  unsigned int i_addr = stoul(addr, nullptr, 16);
  switch (i_addr) {
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
    case flag::G_TEMP_EDI:return true;
  }

  return false;
}

inline bool Propagate::is_mem_load(std::string &addr)
{
    if(XT_Util::equal_mark(addr, flag::TCG_QEMU_LD) )
        return true;
    else
        return false;
}

inline bool Propagate::is_mem_stroe(std::string &addr)
{
    if(XT_Util::equal_mark(addr, flag::TCG_QEMU_ST) || 
       XT_Util::equal_mark(addr, flag::TCG_QEMU_ST_POINTER) )
        return true;
    else
        return false;
}

inline bool Propagate::is_insn_mark(std::string addr)
{
    if(XT_Util::equal_mark(addr, flag::XT_INSN_ADDR) )
        return true;
    else
        return false;
}
