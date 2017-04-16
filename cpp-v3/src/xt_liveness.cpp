#include "xt_constant.h"
#include "xt_flag.h"
#include "xt_liveness.h"
#include "xt_record.h"
#include "xt_util.h"
#include <iostream>
#include <string>
#include <vector>

using namespace std;

void
Liveness::analyze_liveness(bool is_dump,
                           const string curr_t,
                           const xt_file::File& file,
                           const Log& log)
{
  cout << "analyzing liveness..." << endl;
  vector< vector<Record> > alive_func;

  analyze_alive_buf(log, alive_func);
  cout << "num alive function calls: " << alive_func.size() << endl;
  file.write_alive_func(curr_t, alive_func);

  merge_continuous_buf(alive_func);
}

bool Liveness::is_buf_alive(const uint32_t esp, const uint32_t addr)
{
  if(addr >= xt_const::STACK_BEGIN_ADDR ) {
    return is_stack_alive(esp, addr);
  } else {
    return is_heap_alive();
  }
}

bool Liveness::is_stack_alive(const uint32_t esp, const uint32_t addr)
{
  if(addr > esp) { return true; }
  else { return false; }
}

bool Liveness::is_heap_alive()
{
  // heap always consider alive
  return true;
}

void Liveness::analyze_alive_buf(const Log& log,
                                 vector< vector<Record> >& alive_func)
{
  cout << "analyzing alive buffers..." << endl;
  vector<Record> call_stack;
  uint32_t num_func = 0;

  for(auto it_rec = log.get_log().begin(); it_rec != log.get_log().end(); ++it_rec) {
    if(it_rec->is_makr() ) {
      string flag = it_rec->get_const_src_node().get_flag();

      if(util::equal_mark(flag, flag::XT_CALL_INSN)
         || util::equal_mark(flag, flag::XT_CALL_INSN_FF2) ) {
        call_stack.push_back(*it_rec);
      } else if (util::equal_mark(flag, flag::XT_RET_INSN_SEC)
                 && !call_stack.empty() ) {
        // searches call stack reversely
        for(auto it_call = call_stack.rbegin(); it_call != call_stack.rend(); ++it_call) {
          if(util::is_pair_func(it_call->get_const_src_node(),
                                (it_rec-1)->get_const_src_node() ) ) {
            // if pair function call
//            it_call->get_const_src_node().print_node();
//            (it_rec-1)->get_const_src_node().print_node();

            uint32_t c_idx = it_call->get_index();
            uint32_t r_idx = it_rec->get_index();

            vector<Record>::const_iterator it_pair_c = log.get_log().begin() + c_idx;
            vector<Record>::const_iterator it_pair_r = log.get_log().begin() + r_idx + 1;
            vector<Record> pair_func(it_pair_c, it_pair_r);

            vector<Record> pair_func_res = analyze_alive_buf_per_func(pair_func);
            if(pair_func_res.size() > 4) {
              // has valid buffers
//              cout << "pair function res size: " << pair_func_res.size() << endl;
//              for(auto it = pair_func_res.begin(); it != pair_func_res.end(); ++it) {
//                it->print_record();
//              }
              alive_func.push_back(pair_func_res);
            }

            num_func++;
            cout << "analyzing " << num_func << " pair function call..." << endl;
            // erase the call in the stack?
            break;
          }
        } // end fow
      } // end else if
    } else {}
  }
}

vector<Record> Liveness::analyze_alive_buf_per_func(const vector<Record>& pair_func)
{
//  cout << "pair function call size: " << pair_func.size() << endl;
//  for (auto it = pair_func.begin(); it != pair_func.end(); ++it) {
//    it->print_record();
//  }

  vector<Record> v;

  // push call marks
  v.push_back(pair_func[0]);
  v.push_back(pair_func[1]);

  string s_esp = pair_func[0].get_const_src_node().get_addr();
  uint32_t esp = stoul(s_esp, nullptr, 16);

  for(auto it_rec = pair_func.begin()+2; it_rec != pair_func.end()-2; ++it_rec) {
    // Based on the paper, the buffers must:
    // 1) alive: addr > esp of the function call
    // 2) be updated in the function call; that is, is the destination
    //    instead of source
    // 3) There is an issue for list 2), because the program can load
    //    input any time, it also needs to consider load
//    it_rec->print_record();

    if(it_rec->get_mem_type() == flag::M_LOAD) {
      uint32_t addr = it_rec->get_const_src_node().get_int_addr();
      if(is_buf_alive(esp, addr) ) {
        v.push_back(*it_rec);
      }
    }else if(it_rec->get_mem_type() == flag::M_STORE) {
      uint32_t addr = it_rec->get_const_dst_node().get_int_addr();
      if(is_buf_alive(esp, addr) ) {
        v.push_back(*it_rec);
      }
    } else {}
  }

  // push ret marks
  uint32_t sz = pair_func.size();
  v.push_back(pair_func[sz-2]);
  v.push_back(pair_func[sz-1]);

//  for(auto it = v.begin(); it != v.end(); ++it) {
//    it->print_record();
//  }

  return v;
}

void
Liveness::merge_continuous_buf(std::vector< std::vector<Record> >& alive_func)
{

}
