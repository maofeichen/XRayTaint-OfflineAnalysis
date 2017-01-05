#ifndef XT_LIVENESS
#define XT_LIVENESS

#include <string>
#include <vector>

#include "xt_data.h"
#include "xt_log.h"
#include "xt_functioncall.h"

using namespace std;

class XT_Liveness
{
private:
    static const unsigned long STACK_BEGIN_ADDR = 0xb0000000;

    std::vector<std::string> m_s_vAliveBuffer;
    std::vector<XT_FunctionCall> m_vAliveFunctionCall; 

    static inline bool is_mem_alive(unsigned long &, unsigned long &);
    static inline bool is_heap_mem_alive();
    static inline bool is_stack_mem_alive(unsigned long &, unsigned long &);

    static vector<string> analyze_function_alive_buffer(vector<string> &); // IGNORE
    static vector<string> analyze_alive_buffer_per_function(vector<string> &);

    static inline Buf_Rec_t analyze_load_buf(string &);
    static inline Buf_Rec_t analyze_store_buf(string &);
    static bool compare_buf_rec(Buf_Rec_t &, Buf_Rec_t &);

    static vector<t_AliveContinueBuffer> create_continue_buffer(vector<Buf_Rec_t> &);
    static t_AliveFunctionCall analyze_continue_buffer_per_function(vector<string> &);

public:
    XT_Liveness();
    XT_Liveness(std::vector<std::string> &s_vAliveBuffer);

    static std::vector<std::string> analyze_alive_buffer(std::vector<std::string> &xtLog);
    static std::vector<t_AliveFunctionCall> merge_continue_buffer(std::vector<std::string> &);
    static std::vector<t_AliveFunctionCall> filter_continue_buffer(std::vector<t_AliveFunctionCall> &);
    void forceAddTaintBuffer(std::vector<t_AliveFunctionCall> &vFCallContBuf,
                          std::string funcCallMark, 
                          unsigned long beginAddr, 
                          unsigned long size);

    std::vector<string> insert_load_buffer(std::vector<string> &alive_buffer, 
                                           std::vector<string> &xtLog);

    std::vector<XT_FunctionCall> getAliveFunctionCall();
    void create_function_call_buffer(XTLog &xtLog);
    void propagate_alive_buffer();

    std::vector<t_AliveFunctionCall> convert_alive_function_call();
}; 
#endif