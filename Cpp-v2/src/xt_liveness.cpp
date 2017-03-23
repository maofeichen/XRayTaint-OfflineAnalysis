#include <algorithm>
#include <cassert>
#include <iostream>
#include <stack>
#include <string>

#include "xt_constant.h"
#include "xt_flag.h"
#include "xt_liveness.h"
#include "xt_util.h"

XT_Liveness::XT_Liveness(){}

XT_Liveness::XT_Liveness(std::vector<std::string> &s_vAliveBuffer)
{
    m_s_vAliveBuffer = s_vAliveBuffer;
}

// analyzes alive buffers for each function call given a xtlog.
// For those buffers are alive for multiple nested function call,
// they are ONLY considerred alive in the innermost function call.
// args:
//      - xtlog: a vector of strings that contains all xtaint records
// return:
//      - alive_buffer: a vector contaiins all alive buffers of each function
//          call. And function calls are sorted with ended first order.
vector<string> XT_Liveness::analyze_alive_buffer(vector<string> &xtLog)
{
    int index;
    int indexCall;
    int indexRet;
    unsigned int funcCallIndex = 0;
    string ret;
    string call;
    vector<string> alive_buffer;
    vector<string> temp;
    vector<string>::iterator it_call;
    vector<string>::iterator it_ret;

    std::cout << "Analyzing alive buffers..." << endl;

    unsigned long numFunction = 1;

    for(vector<string>::iterator it = xtLog.begin(); it != xtLog.end(); ++it){
        // If a function call END mark hit
        if(XT_Util::equal_mark(*it, flag::XT_RET_INSN_SEC) ){
            // ret is previous of 2nd ret mark
            ret = *(it - 1);    
            index = xtLog.end() - it;

            // scan backward to the begin
            vector<string>::reverse_iterator rit = xtLog.rbegin() + index - 1;
            for(; rit != xtLog.rend(); ++rit){
                // if a CALL mark hits
                if(XT_Util::equal_mark(*rit, flag::XT_CALL_INSN) || 
                    XT_Util::equal_mark(*rit, flag::XT_CALL_INSN_FF2) ){
                    call = *rit;
                    // if a matched CALL & RET marks
                    if(XT_Util::is_pair_function_mark(call, ret) ){

                        cout << "Analyzing " << numFunction << " function call..." << endl;
                        numFunction++;

                        indexCall = xtLog.rend() - rit;
                        indexRet = it - xtLog.begin();

                        it_call = xtLog.begin() + indexCall - 1;
                        it_ret = xtLog.begin() + indexRet + 1;
                        vector<string> v_function_call(it_call, it_ret);

                        temp = XT_Liveness::analyze_alive_buffer_per_function(v_function_call);

                        if(funcCallIndex == 0){
                            // Only for first matched function call, 
                            // collects all previous Qemu Load buffers
                        }

                        // Indicates the function call contains valid buffers
                        if(temp.size() > 4){
                            for(vector<string>::iterator tempIt = temp.begin(); tempIt != temp.end(); ++tempIt)
                                alive_buffer.push_back(*tempIt);
                        }

                        funcCallIndex++;
                        break;  // break search backward
                    }
                }
            }
        }
    }

    return alive_buffer;
}

// !!! IGNORE
// analyzes alive buffers for a particular function call.
vector<string> XT_Liveness::analyze_function_alive_buffer(vector<string> &v)
{
    vector<string> v_new;
    stack<string> nest_function;
    bool is_in_nest_function = false;
    int idx;
    vector<string>::iterator it_call, it_ret;

    // push outermost CALL marks
    v_new.push_back(v[0]);
    v_new.push_back(v[1]);

    for(vector<string>::iterator it = v.begin() + 2; it != v.end() - 2; ++it){
        // If a nested CALL mark hits
        if(XT_Util::equal_mark(*it, flag::XT_CALL_INSN) || 
            XT_Util::equal_mark(*it, flag::XT_CALL_INSN_FF2) ){
            // if already in nested function, no need to check
            if(!is_in_nest_function){
                idx = it - v.begin();
                it_call = it;
                // finds its matched RET mark
                for(it_ret = v.begin() + idx; it_ret != v.end() - 2; ++it_ret){
                    // if a RET mark hits
                    if(XT_Util::equal_mark(*it_ret, flag::XT_RET_INSN))
                        if(XT_Util::is_pair_function_mark(*it_call, *it_ret) ){
                            is_in_nest_function = true;
                            nest_function.push(*it_call);
                            break;
                        }
                }
            }
        }
        // if a nested RET mark hit
        else if(XT_Util::equal_mark(*it, flag::XT_RET_INSN)){
            if(!nest_function.empty() && XT_Util::is_pair_function_mark(nest_function.top(), *it) ){
                nest_function.pop();
                is_in_nest_function = false;
            }
        }
        // if a mem buffer mark hits
        else if(XT_Util::equal_mark(*it, flag::TCG_QEMU_LD) || 
            XT_Util::equal_mark(*it, flag::TCG_QEMU_ST))
            if(!is_in_nest_function)
                v_new.push_back(*it);
    }

    // push outer most RET marks
    v_new.push_back(v[v.size() - 2]);
    v_new.push_back(v[v.size() - 1]);

    return v_new;
}

// analyzes alive buffers for a particular function call
vector<string> XT_Liveness::analyze_alive_buffer_per_function(vector<string> &v)
{
    vector<string> v_new, v_call_mark, v_ld, v_st;
    string call_mark, s_func_esp, s_mem_addr;
    unsigned long i_func_esp, i_mem_addr;

    call_mark = v[0];
    v_call_mark = XT_Util::split(call_mark.c_str(), '\t');
    s_func_esp = v_call_mark[1];
    // std::cout << "size of esp string: " << s_func_esp.size() << std::endl;
    i_func_esp = std::stoul(s_func_esp, nullptr, 16);

    // push outermost CALL marks
    v_new.push_back(v[0]);
    v_new.push_back(v[1]);

    for(vector<string>::iterator it = v.begin() + 2; it != v.end() - 2; ++it){
        // Based on the paper, the buffers should: 
        // 1) alive
        // 2) be updated in the function call; that is, is the destination
        //    instead of source
        // 3) There is a issue for list 2), because the program can load
        //    input any time, so it also needs to consider load
        if(XT_Util::equal_mark(*it, flag::TCG_QEMU_ST)){
            v_st = XT_Util::split((*it).c_str(), '\t');
            s_mem_addr = v_st[4];
            i_mem_addr = std::stoul(s_mem_addr, nullptr, 16);
            if(is_mem_alive(i_func_esp, i_mem_addr) )
                v_new.push_back(*it);
        }
        else if(XT_Util::equal_mark(*it, flag::TCG_QEMU_LD) ){
            // Debug
            v_ld = XT_Util::split((*it).c_str(), '\t');
            s_mem_addr = v_ld[1];
            i_mem_addr = stoul(s_mem_addr, nullptr, 16);
            if(is_mem_alive(i_func_esp, i_mem_addr) ) {
                v_new.push_back(*it);
            }
        }
    }

    // push outer most RET marks
    v_new.push_back(v[v.size() - 2]);
    v_new.push_back(v[v.size() - 1]);

    return v_new;
}

inline bool XT_Liveness::is_mem_alive(unsigned long &func_esp, unsigned long &mem_addr)
{
    if(mem_addr > STACK_BEGIN_ADDR)
        is_stack_mem_alive(func_esp, mem_addr);
    else
        is_heap_mem_alive();
}

inline bool XT_Liveness::is_stack_mem_alive(unsigned long &func_esp, unsigned long &stack_addr)
{
    if(stack_addr > func_esp)
        return true;
    else
        return false;
}

// heap addr always consider alive
inline bool XT_Liveness::is_heap_mem_alive()
{
    return true;
}

// merge continue buffers for all function calls in xtaint log
vector<t_AliveFunctionCall> XT_Liveness::merge_continue_buffer(vector<string> &v)
{
    vector<string>::iterator it_call, it_ret;
    t_AliveFunctionCall func_call_cont_buf;
    vector<t_AliveFunctionCall> v_func_call_cont_buf;

    std::cout << "Merging continue buffer..." << endl;

    for(vector<string>::iterator it = v.begin(); it != v.end(); ++it){
        if(XT_Util::equal_mark(*it, flag::XT_CALL_INSN) ||
            XT_Util::equal_mark(*it, flag::XT_CALL_INSN_FF2) ){
            it_call = it;
            for(it_ret = it_call + 1; it_ret != v.end(); ++it_ret){
                // find call mark coresponding ret mark
                if(XT_Util::equal_mark(*it_ret, flag::XT_RET_INSN_SEC)){
                    vector<string> v_function_call(it_call, it_ret + 1);
                    func_call_cont_buf = XT_Liveness::analyze_continue_buffer_per_function(v_function_call);
                    v_func_call_cont_buf.push_back(func_call_cont_buf);
                    break;
                }
            }
        }

    }

    return v_func_call_cont_buf;
}

inline bool XT_Liveness::isHasAliveBuffer(t_AliveFunctionCall &aliveFunction, t_AliveContinueBuffer &aliveBuffer)
{
    bool isHas = false;

    vector<t_AliveContinueBuffer>::iterator itAliveBuf = aliveFunction.vAliveContinueBuffer.begin();
    for(; itAliveBuf != aliveFunction.vAliveContinueBuffer.end(); ++itAliveBuf){
        if(aliveBuffer.beginAddress == (*itAliveBuf).beginAddress && 
           aliveBuffer.size == (*itAliveBuf).size)
            isHas = true;
    } 

    return isHas;
}

// merge continues buffer if any for a particular function call
t_AliveFunctionCall XT_Liveness::analyze_continue_buffer_per_function(vector<string> &v)
{
    t_AliveFunctionCall func_call_cont_buf;
    vector<t_AliveContinueBuffer> v_cont_buf;
    Buf_Rec_t buf_rec;
    vector<Buf_Rec_t> v_buf_rec;

    func_call_cont_buf.call_mark = v[0];
    func_call_cont_buf.sec_call_mark = v[1];

    for(vector<string>::iterator it = v.begin() + 2; it != v.end() - 2; ++it){
        if(XT_Util::equal_mark(*it, flag::TCG_QEMU_LD) ){
            buf_rec = XT_Liveness::analyze_load_buf(*it);
            v_buf_rec.push_back(buf_rec);
        }
        else if(XT_Util::equal_mark(*it, flag::TCG_QEMU_ST) ){
            buf_rec = XT_Liveness::analyze_store_buf(*it);
            v_buf_rec.push_back(buf_rec);
        }
    }

    std::sort(v_buf_rec.begin(), v_buf_rec.end(), XT_Liveness::compare_buf_rec);
    v_cont_buf = XT_Liveness::create_continue_buffer(v_buf_rec);
    func_call_cont_buf.vAliveContinueBuffer = v_cont_buf;

    func_call_cont_buf.ret_mark = v[v.size() - 2];
    func_call_cont_buf.sec_ret_mark = v[v.size() - 1];

    return func_call_cont_buf;
}

inline Buf_Rec_t XT_Liveness::analyze_load_buf(string &s)
{
    Buf_Rec_t buf_rec;
    vector<string> v_ld_rec;

    v_ld_rec = XT_Util::split(s.c_str(), '\t');
    buf_rec.src_flag = v_ld_rec[0];
    buf_rec.src_addr = v_ld_rec[1];
    buf_rec.src_val = v_ld_rec[2];

    buf_rec.dst_flag = v_ld_rec[3];
    buf_rec.dst_addr = v_ld_rec[4];
    buf_rec.dst_val = v_ld_rec[5];

    buf_rec.s_size = v_ld_rec[6];
    buf_rec.this_rec = s;

    buf_rec.addr = std::stoul(buf_rec.src_addr, nullptr, 16);
    buf_rec.size = std::stoul(buf_rec.s_size, nullptr, 10);

    return buf_rec;
}

inline Buf_Rec_t XT_Liveness::analyze_store_buf(string &s)
{
    Buf_Rec_t buf_rec;
    vector<string> v_st_rec;

    v_st_rec = XT_Util::split(s.c_str(), '\t');
    buf_rec.src_flag = v_st_rec[0];
    buf_rec.src_addr = v_st_rec[1];
    buf_rec.src_val = v_st_rec[2];

    buf_rec.dst_flag = v_st_rec[3];
    buf_rec.dst_addr = v_st_rec[4];
    buf_rec.dst_val = v_st_rec[5];

    buf_rec.s_size = v_st_rec[6];
    buf_rec.this_rec = s;

    buf_rec.addr = std::stoul(buf_rec.dst_addr, nullptr, 16);
    buf_rec.size = std::stoul(buf_rec.s_size, nullptr, 10);

    return buf_rec;
}

bool XT_Liveness::compare_buf_rec(Buf_Rec_t &b1, Buf_Rec_t &b2)
{
    return b1.addr < b2.addr;
}

vector<t_AliveContinueBuffer> XT_Liveness::create_continue_buffer(vector<Buf_Rec_t> &v_buf_rec)
{
    vector<t_AliveContinueBuffer> v_cont_buf;
    t_AliveContinueBuffer vAliveContinueBuffer;

    vAliveContinueBuffer.beginAddress = v_buf_rec[0].addr;
    vAliveContinueBuffer.size = v_buf_rec[0].size;
    for(vector<Buf_Rec_t>::iterator it = v_buf_rec.begin() + 1; it != v_buf_rec.end(); ++it){
        // if addr already contain
        if((vAliveContinueBuffer.beginAddress + vAliveContinueBuffer.size / 8) > (*it).addr)
            continue;
        // if continue
        else if((vAliveContinueBuffer.beginAddress + vAliveContinueBuffer.size / 8) == (*it).addr )
            vAliveContinueBuffer.size += (*it).size;
        // if discontinue
        else if((vAliveContinueBuffer.beginAddress + vAliveContinueBuffer.size / 8) < (*it).addr){
            v_cont_buf.push_back(vAliveContinueBuffer);
            vAliveContinueBuffer.beginAddress = (*it).addr;
            vAliveContinueBuffer.size = (*it).size;
        }
    }

    return v_cont_buf;
}

// fliter continue buffers that size larger than 4 bytes
vector<t_AliveFunctionCall> XT_Liveness::filter_continue_buffer(vector<t_AliveFunctionCall> &v)
{
    t_AliveFunctionCall func_call_cont_buf;
    vector<t_AliveFunctionCall> v_new;

    std::cout << "Filtering continue buffers size > 4 bytes..." << endl;

    for(vector<t_AliveFunctionCall>::iterator it_func = v.begin(); it_func != v.end(); ++it_func){
        func_call_cont_buf.call_mark = (*it_func).call_mark;
        func_call_cont_buf.sec_call_mark = (*it_func).sec_call_mark;
        func_call_cont_buf.ret_mark = (*it_func).ret_mark;
        func_call_cont_buf.sec_ret_mark = (*it_func).sec_ret_mark;

        for(vector<t_AliveContinueBuffer>::iterator it_cont_buf = (*it_func).vAliveContinueBuffer.begin();
            it_cont_buf != (*it_func).vAliveContinueBuffer.end(); ++it_cont_buf){
            if((*it_cont_buf).size > 32)
                func_call_cont_buf.vAliveContinueBuffer.push_back(*it_cont_buf);
        }
        v_new.push_back(func_call_cont_buf);
        func_call_cont_buf.vAliveContinueBuffer.clear();
    }

    return v_new;
}

// Force add taint buffer as alive buffer into the liveness analysis result
void XT_Liveness::forceAddTaintBuffer(vector<t_AliveFunctionCall> &vFCallContBuf,
                                      string funcCallMark,
                                      unsigned long beginAddr, unsigned long size)
{
    t_AliveContinueBuffer contBuf;
    contBuf.beginAddress = beginAddr;
    contBuf.size = size;

    vector<t_AliveFunctionCall>::iterator it = vFCallContBuf.begin();
    for(; it != vFCallContBuf.end(); ++it){
       if( (*it).call_mark == funcCallMark)
           (*it).vAliveContinueBuffer.push_back(contBuf); 
    }
    // vFCallContBuf[0].vAliveContinueBuffer.push_back(contBuf);
}

// Given results of analyze_alive_buffer, in first function call
// completion, insert all qemu load buffers that before this
// function call
vector<string> XT_Liveness::insert_load_buffer(
    vector<string> &alive_buffer, 
    vector<string> &xtLog
    )
{
    vector<string> new_alive_buffer;

    cout << "Inserting load buffers at first function call completion..." << endl;

    bool firstHit = false;
    string firstRetMark = "";
    string flag = ""; 
    vector<string> vRecord;

    vector<string>::iterator it_ab = alive_buffer.begin();
    for(; it_ab != alive_buffer.end(); ++it_ab){
        vRecord = XT_Util::split((*it_ab).c_str(), '\t');
        flag = vRecord[0];

        // found first return mark in alive buffers
        if(XT_Util::equal_mark(flag, flag::XT_RET_INSN) &&
           !firstHit){
            firstRetMark = *it_ab;

            vector<string>::iterator it_xt = xtLog.begin();
            for(; it_xt != xtLog.end(); ++it_xt){
                if(firstRetMark == *it_xt)
                    break;

                vRecord = XT_Util::split((*it_xt).c_str(), '\t');
                flag = vRecord[0];
                                
                if(XT_Util::equal_mark(flag, flag::TCG_QEMU_LD) ){
                    new_alive_buffer.push_back(*it_xt);
                }
            }

            firstHit = true;
        }

        new_alive_buffer.push_back(*it_ab);
    }

    return new_alive_buffer; 
}

vector<XT_FunctionCall> XT_Liveness::getAliveFunctionCall() 
{ 
    return m_vAliveFunctionCall; 
}

// Create continuous buffers for each function call
vector<t_AliveFunctionCall> XT_Liveness::create_function_call_buffer(XTLog &xtLog)
{
    vector<t_AliveFunctionCall> vAliveFunction;
    t_AliveFunctionCall aAliveFunction;

    vector<string>::iterator itCall;
    vector<string>::iterator itRet;

    std::cout << "Creating continue buffer for function calls..." << endl;

    unsigned int numFunction = 1;
    vector<string>::iterator it = m_s_vAliveBuffer.begin();
    for(; it != m_s_vAliveBuffer.end(); ++it){
        if(XT_Util::equal_mark(*it, flag::XT_CALL_INSN) || 
           XT_Util::equal_mark(*it, flag::XT_CALL_INSN_FF2) ){
            itCall = it;

            for(itRet = itCall + 1; itRet != m_s_vAliveBuffer.end(); ++itRet){
                // find matched ret marks
                if(XT_Util::equal_mark(*itRet, flag::XT_RET_INSN_SEC) ){
                    vector<string> s_aFunctionCallBuffer(itCall, itRet + 1);
                    XT_FunctionCall aFunctionCallBuffer(s_aFunctionCallBuffer, xtLog);

                    aAliveFunction = aFunctionCallBuffer.merge_continuous_buffer();
                    vAliveFunction.push_back(aAliveFunction);

                    // Not used! 
                    // m_vAliveFunctionCall.push_back(aFunctionCallBuffer);

                    cout << "Liveness Analysis: Num of function call had been scanned: " << numFunction << endl;
                    numFunction++;
                    break; 
                }
            }
        }
    }
    cout << "Liveness Analysis: total number of function calls: " << numFunction << endl;

    return vAliveFunction;
}

// Filter out buffer size smaller than 8 bytes
void XT_Liveness::filter_small_continuous_buffer()
{
    cout << "Filtering out small continuous buffer..." << endl;

    vector<XT_FunctionCall>::iterator itFunction = m_vAliveFunctionCall.begin();
    for(; itFunction != m_vAliveFunctionCall.end(); ++itFunction){

        vector<XT_AliveBuffer> vAliveBuffer = (*itFunction).getAliveBuffers();
        vector<XT_AliveBuffer>::iterator itBuffer = vAliveBuffer.begin(); 
        for(; itBuffer != vAliveBuffer.end(); ++itBuffer){
            if( (*itBuffer).getBufferByteSize() < VALID_BYTE_SIZE){
                (*itFunction).removeAliveBuffer(*itBuffer);
            }
        }
    }
}

vector<t_AliveFunctionCall> 
XT_Liveness::filter_kernel_buffer(vector<t_AliveFunctionCall> &vAliveFunction)
{
    cout << "Filtering out kernel continuous buffer..." << endl;

    vector<t_AliveFunctionCall> vAliveFunctionNew;
    t_AliveFunctionCall aliveFunction;

    vector<t_AliveFunctionCall>::iterator itFunction = vAliveFunction.begin();
    for(; itFunction != vAliveFunction.end(); ++itFunction){

        aliveFunction.call_mark     = (*itFunction).call_mark;
        aliveFunction.sec_call_mark = (*itFunction).sec_call_mark;
        aliveFunction.ret_mark      = (*itFunction).ret_mark;
        aliveFunction.sec_ret_mark  = (*itFunction).sec_ret_mark;

        aliveFunction.vAliveContinueBuffer.clear();

        vector<t_AliveContinueBuffer>::iterator itBuffer = (*itFunction).vAliveContinueBuffer.begin();
        for(; itBuffer != (*itFunction).vAliveContinueBuffer.end(); ++itBuffer){
            if( (*itBuffer).beginAddress < KERNEL_ADDRESS){
                // (*itFunction).vAliveContinueBuffer.erase(itBuffer);
                aliveFunction.vAliveContinueBuffer.push_back(*itBuffer);
            } 
        }
        if(!aliveFunction.vAliveContinueBuffer.empty() ){
            vAliveFunctionNew.push_back(aliveFunction);
        }
        // vAliveFunctionNew.push_back(aliveFunction); 
    }

    return vAliveFunctionNew;
}

void clean_empty_function(std::vector<t_AliveFunctionCall> &vAliveFunction)
{

}

// If any alive buffer still alive in next function call,
// propagate to all next function calls
void XT_Liveness::propagate_alive_buffer(vector<t_AliveFunctionCall> &vAliveFunction)
{
    cout << "Propagating alive buffers to next function call..." << endl;

    vector<t_AliveFunctionCall>::iterator itFunction = vAliveFunction.begin();
    for(; itFunction != vAliveFunction.end() - 1; ++itFunction){

        vector<t_AliveContinueBuffer> vAliveBuffer = (*itFunction).vAliveContinueBuffer;
        vector<t_AliveContinueBuffer>::iterator it_alive_buf = vAliveBuffer.begin();

        for(; it_alive_buf != vAliveBuffer.end(); ++it_alive_buf){
            vector<t_AliveFunctionCall>::iterator itNextFunction = itFunction + 1;
            // If still alive in all next function call
            for(; itNextFunction != vAliveFunction.end(); ++itNextFunction){
                vector<string> vCallMark = XT_Util::split((*itNextFunction).call_mark.c_str(), '\t');
                string sESP = vCallMark[1];
                unsigned long esp = stoul(sESP, nullptr, 16);
                if( (*it_alive_buf).beginAddress >= esp ){
                    if(!isHasAliveBuffer(*itNextFunction, *it_alive_buf) ){
                        (*itNextFunction).vAliveContinueBuffer.push_back(*it_alive_buf);
                    }
                }
            }
        }
    } 
}

// Converts m_vAliveFunction to struct t_AliveFunctionCall for
// further search avalanche 
vector<t_AliveFunctionCall> XT_Liveness::convert_alive_function_call()
{
    cout << "Converting to struct t_AliveFunctionCall..." << endl;

    vector<t_AliveFunctionCall> v_alive_function_call;
    t_AliveFunctionCall alive_function_call;

    t_AliveContinueBuffer alive_continue_buffer;

    vector<XT_FunctionCall>::iterator it_fc = m_vAliveFunctionCall.begin();
    for(; it_fc != m_vAliveFunctionCall.end(); ++it_fc){

        alive_function_call.call_mark       = (*it_fc).getFirstCallMark();
        alive_function_call.sec_call_mark   = (*it_fc).getSecondCallMark();
        alive_function_call.ret_mark        = (*it_fc).getFirstRetMark();
        alive_function_call.sec_ret_mark    = (*it_fc).getSecondRetMark();

        vector<XT_AliveBuffer> v_alive_buffer = (*it_fc).getAliveBuffers();
        vector<XT_AliveBuffer>::iterator it_ab = v_alive_buffer.begin();

        for(; it_ab != v_alive_buffer.end(); ++it_ab){
            alive_continue_buffer.beginAddress  = (*it_ab).getBeginAddr();
            alive_continue_buffer.size          = (*it_ab).getBufferBitSize();
            alive_function_call.vAliveContinueBuffer.push_back(alive_continue_buffer);
        }

        v_alive_function_call.push_back(alive_function_call);
        alive_function_call.vAliveContinueBuffer.clear();
    }

    return v_alive_function_call;
}
