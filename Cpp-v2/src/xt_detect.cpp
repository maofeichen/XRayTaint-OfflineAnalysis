#include "xt_detect.h"

#include <iostream>

using namespace std;

Detect::Detect(vector<t_AliveFunctionCall> v_func_cont_buf,
		       XTLog &xt_log)
{
    v_func_cont_buf_ = v_func_cont_buf;
    xt_log_ = xt_log;
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

void Detect::detect_cipher_in_out(t_AliveContinueBuffer &in,
	                              t_AliveContinueBuffer &out)
{

}
