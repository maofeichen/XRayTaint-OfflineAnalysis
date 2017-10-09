#include <fstream>
#include <iostream>
#include <vector>

#include "xt_file.h"
#include "xt_flag.h"
#include "xt_util.h"

XT_File::XT_File(std::string path)
{
    path_r = path;
}

std::vector<std::string> XT_File::read()
{
    std::ifstream xt_file(path_r.c_str() );
    std::vector<std::string> v;
    std::string line;
    int i;

//    i = 0;
    if(xt_file.is_open() ){
        while(getline(xt_file, line) ){
            if(i == 453)
                std::cout << "Index: " << i << std::endl;
            v.push_back(line);
//            i++;
        }
    }
    else
        std::cout << "error open file: " << path_r << std::endl;
    xt_file.close();

    // std::cout << "read file: " << path_r << std::endl;
    // for(std::vector<std::string>::iterator it = v.begin(); it != v.end(); ++it)
    //     std::cout << *it << std::endl;

    return v;
}

void XT_File::read(std::vector<std::string>& log)
{
    std::ifstream xt_file(path_r.c_str() );

    if(xt_file.is_open() ){
        string prev_line;
        string curr_line;

        int num_line = 1;

        getline(xt_file, prev_line);
        while (getline(xt_file, curr_line)) {
            string prev_flag = prev_line.substr(0,2);
            string curr_flag = curr_line.substr(0,2);
            if(XT_Util::equal_mark(curr_flag, flag::XT_INSN_ADDR)
                && XT_Util::equal_mark(prev_flag, flag::XT_INSN_ADDR) ) {

            } else {
                log.push_back(curr_line);
            }

            prev_line = curr_line;
            num_line++;
        }
        cout << "total lines scanned: " << num_line << endl;
    }
    else
        std::cout << "error open file: " << path_r << std::endl;
    xt_file.close();

    // std::cout << "read file: " << path_r << std::endl;
    // for(std::vector<std::string>::iterator it = v.begin(); it != v.end(); ++it)
    //     std::cout << *it << std::endl;
}

void XT_File::write(string p, vector<string> &v)
{
    ofstream f(p.c_str());

    if(f.is_open()){
        for(vector<string>::iterator it = v.begin(); it != v.end(); ++it)
            f << *it <<'\n';

        f.close();
    }
    else
        cout << "error open file: " << p << endl;
}


void XT_File::write_continue_buffer(string p, vector<t_AliveFunctionCall> &v)
{
    ofstream f(p.c_str());

    if(f.is_open()){
        for(vector<t_AliveFunctionCall>::iterator it_func = v.begin();
            it_func != v.end(); ++it_func){
            f << "Function Call: " << '\n';
            f << (*it_func).call_mark << '\n';
            f << (*it_func).sec_call_mark << '\n';

            for(vector<t_AliveContinueBuffer>::iterator it_cont_buf = (*it_func).vAliveContinueBuffer.begin();
                it_cont_buf != (*it_func).vAliveContinueBuffer.end(); ++it_cont_buf){
                f << "Begin_Addr: " << hex << (*it_cont_buf).beginAddress << '\n';
                f << "Size: " << dec << (*it_cont_buf).size / 8  << " bytes" << '\n';
            }

            f << (*it_func).ret_mark << '\n';
            f << (*it_func).sec_ret_mark << '\n';
        }
        f.close();
    }
    else
        cout << "error open file: " << p << std::endl;
}

void XT_File::write_continuous_buffer(
    std::string path, 
    XT_Liveness &function_call_liveness
    )
{
    ofstream xt_file(path.c_str() );

    cout << "Writing continuous buffers..." << endl;

    if(xt_file.is_open() ){
        vector<XT_FunctionCall> vFunctionCall = function_call_liveness.getAliveFunctionCall();

        unsigned int index = 0;
        vector<XT_FunctionCall>::iterator it = vFunctionCall.begin();
        for(; it != vFunctionCall.end(); ++it){
            xt_file << "---------- ----------" << '\n';
            xt_file << "Function Call " << index << '\n';
            xt_file << "---------- ----------" << '\n';

            xt_file << "First Call Mark: " << (*it).getFirstCallMark() << '\n';
            xt_file << "Second Call Mark: " << (*it).getSecondCallMark() << '\n';
            xt_file << "----------" << '\n';

            vector<XT_AliveBuffer> vAliveBuffer = (*it).getAliveBuffers();
            vector<XT_AliveBuffer>::iterator it_alive_buffer = vAliveBuffer.begin();
            for(; it_alive_buffer != vAliveBuffer.end(); ++it_alive_buffer){
                xt_file << "Begin Address: " << hex << (*it_alive_buffer).getBeginAddr() << '\n';
                xt_file << "Byte Size: " << dec << (*it_alive_buffer).getBufferByteSize() << '\n';
                xt_file << "----------" << '\n';
            }

            xt_file << "First Ret Mark: " << (*it).getFirstRetMark() << '\n';
            xt_file << "Second Ret Mark: " << (*it).getSecondRetMark() << '\n';

            index++;
        }

    } else
        cout << "error open file: " << path << endl;

    xt_file.close();
}

void XT_File::write_all_propagate_result(string path, vector<NodePropagate> &allPropagateRes)
{
    int layer = 0;
    string insnAddr = "";
    ofstream file(path.c_str() );
    if(file.is_open() ){
        file << "Total Propagates: " << allPropagateRes.size() << endl;
        file << "------------------------------" << endl;

        for (auto s : allPropagateRes){
            if(layer != s.layer){
                layer = s.layer;
                file << "------------------------------" << endl;
            }
            if(insnAddr != s.insnAddr){
                insnAddr = s.insnAddr;
                file << "==============================" << endl;
                file << "guest insn addr: " << insnAddr << endl;
                file << "==============================" << endl;
            }
            file << "layer: " << s.layer;
            file << "\tid: " << s.id;
            file << "\tparent id: " << s.parentId;
            if(s.isSrc)
                file << "\tsrc" << endl;
            else
                file << "\tdst" << endl;

            file << "flag: " << s.n.flag;
            file << "\taddr: " << s.n.addr;
            file << "\tval: " << s.n.val << '\n' << endl;
        }
        file.close();
    } else
        cout << "error open file: " << path << endl;
}

void XT_File::writeAvalancheResult(std::string p, std::vector<AvalancheResBetweenInAndOut> &vAvalRes)
{
    SearchAvalanche sa;

    freopen(p.c_str(), "w", stdout);
    if(!vAvalRes.empty() ){
        vector<AvalancheResBetweenInAndOut>::iterator it = vAvalRes.begin();
        for(; it != vAvalRes.end(); ++it){
            cout << "---------- ---------- ---------- ----------" << endl;
            sa.printAvalResBetweenInAndOut(*it);
        }
    }
    fclose(stdout);
}

void XT_File::writeAvalResult(std::string p, std::vector<AvalResBetweenInOut> &vAvalRes)
{
    SearchAvalanche sa;

    freopen(p.c_str(), "w", stdout);
    if(!vAvalRes.empty() ){
        vector<AvalResBetweenInOut>::iterator it = vAvalRes.begin();
        for(; it != vAvalRes.end(); ++it){
            cout << "---------- ---------- ---------- ----------" << endl;
            sa.printAvalResBetweenInAndOutNew(*it);
        }
    }
    fclose(stdout);
}
