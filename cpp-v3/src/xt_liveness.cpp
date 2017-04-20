#include "xt_constant.h"
#include "xt_flag.h"
#include "xt_liveness.h"
#include "xt_record.h"
#include "xt_util.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <stdexcept>
#include <vector>

using namespace std;

void
Liveness::analyze_liveness(const Log& log,
                           vector< std::vector<Record> >& r_alive_func,
                           vector<AliveFunction>& v_liveness)
{
  cout << "analyzing liveness..." << endl;
  analyze_alive_buf(log, r_alive_func);

  merge_continuous_buf(r_alive_func, v_liveness);

  filter_invalid_cont_buf(v_liveness);
  filter_kernel_buf(v_liveness);
//  print_liveness(v_liveness_res);
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
Liveness::merge_continuous_buf(const vector< vector<Record> >& all_alive_func,
                               std::vector<AliveFunction>& v_liveness)
{
  for(auto it_func = all_alive_func.begin(); it_func != all_alive_func.end(); ++it_func) {
    AliveFunction alive_func_res;
    merge_continuous_buf_per_func(alive_func_res, *it_func);
//    print_liveness_func(alive_func_res);
    v_liveness.push_back(alive_func_res);
  }

}


void
Liveness::merge_continuous_buf_per_func(AliveFunction& alive_func_res,
                                        const vector<Record>& alive_func)
{
  uint32_t sz = alive_func.size();
  alive_func_res.set_fir_c_mark(alive_func[0].get_const_src_node() );
  alive_func_res.set_sec_c_mark(alive_func[1].get_const_src_node() );
  alive_func_res.set_fir_r_mark(alive_func[sz-2].get_const_src_node() );
  alive_func_res.set_sec_r_mark(alive_func[sz-1].get_const_src_node() );

  vector<Node> alive_node;

//  alive_func.begin()->get_const_src_node().print_node();
//  (alive_func.begin()+1)->get_const_src_node().print_node();

//  alive_node.push_back(alive_func.begin()->get_const_src_node() );
//  alive_node.push_back( (alive_func.begin()+1)->get_const_src_node() );

  for(auto it_rec = alive_func.begin()+2; it_rec != alive_func.end()-2; ++it_rec) {
    // breaks records into memory nodes
    if(it_rec->get_mem_type() == flag::M_LOAD) {
      alive_node.push_back(it_rec->get_const_src_node() );
    }else if(it_rec->get_mem_type() == flag::M_STORE) {
      alive_node.push_back(it_rec->get_const_dst_node() );
    }
  }

//  (alive_func.end()-2)->get_const_src_node().print_node();
//  (alive_func.end()-1)->get_const_src_node().print_node();

//  alive_node.push_back((alive_func.end()-2)->get_const_src_node() );
//  alive_node.push_back((alive_func.end()-1)->get_const_src_node() );

  analyze_alive_node(alive_func_res, alive_node);
}

// alive_node only contains memory nodes
void
Liveness::analyze_alive_node(AliveFunction& alive_func_res,
                             vector<Node>& alive_node)
{
  uint32_t sz = alive_node.size();
//  cout << "num of node in alive function: " << sz << endl;
//  alive_node[0].print_node();
//  alive_node[1].print_node();
//  alive_node[sz-2].print_node();
//  alive_node[sz-1].print_node();

  // sanity test
  for(auto it_node = alive_node.begin(); it_node != alive_node.end(); ++it_node) {
//    cout << "node idx: " << dec << it_node->get_index() << endl;
    if(!it_node->is_mem() ) {
      throw runtime_error("error: creating continuous buffer - given node is not a mem node.");
    }
  }

//  cout << "before sorting: " << endl;
//  for(auto it = alive_node.begin(); it != alive_node.end(); ++it) {
//    it->print_mem_node();
//  }

  sort(alive_node.begin(), alive_node.end() );

//  cout << "after sorting: " << endl;
//  for(auto it = alive_node.begin(); it != alive_node.end(); ++it) {
//    it->print_mem_node();
//  }

  create_continuous_buf(alive_func_res, alive_node);
}

void
Liveness::create_continuous_buf(AliveFunction& alive_func_res,
                                const vector<Node>& alive_node)
{
  uint32_t accum_byte_sz = 0;

  ContinueBuf cont_buf;
  cont_buf.set_begin(alive_node.begin()->get_int_addr() );
  cont_buf.set_byte_sz(alive_node.begin()->get_sz_byte() );
  cont_buf.add_node_idx(alive_node.begin()->get_index() );
  accum_byte_sz = alive_node.begin()->get_sz_byte();

//  Cont_Buf_ cont_buf;
//  cont_buf.begin_addr = alive_node.begin()->get_int_addr();
//  cont_buf.byte_sz    = alive_node.begin()->get_sz_byte();
//  accum_byte_sz       = cont_buf.byte_sz;
//  cont_buf.v_node_idx.push_back(alive_node.begin()->get_index() );

  for(auto it_node = alive_node.begin()+1; it_node != alive_node.end(); ++it_node) {
    uint32_t curr_addr = cont_buf.get_begin() + cont_buf.get_byte_sz();

    if(curr_addr > it_node->get_int_addr() ) {
      // in the current range
      cont_buf.add_node_idx(it_node->get_index() );
//      cont_buf.v_node_idx.push_back( );
    } else if(curr_addr == it_node->get_int_addr() ) {
      // extend the range
      accum_byte_sz    += it_node->get_sz_byte();
      uint32_t curr_sz = cont_buf.get_byte_sz();
      curr_sz          += it_node->get_sz_byte();
      cont_buf.set_byte_sz(curr_sz);
      cont_buf.add_node_idx(it_node->get_index() );

//      cont_buf.byte_sz += it_node->get_sz_byte();
//      cont_buf.v_node_idx.push_back(it_node->get_index() );
    } else {
      // out of range
      // saves current continuous buffer
      alive_func_res.add_cont_buf(cont_buf);
//      alive_func_res.v_cont_buf.push_back(cont_buf);

      // re-init
      cont_buf.set_begin(it_node->get_int_addr() );
      cont_buf.set_byte_sz(it_node->get_sz_byte() );
      cont_buf.clear_node_idx();
      cont_buf.add_node_idx(it_node->get_index() );
      accum_byte_sz       = it_node->get_sz_byte();


//      cont_buf.begin_addr = it_node->get_int_addr();
//      accum_byte_sz       = it_node->get_sz_byte();
//      cont_buf.byte_sz    = it_node->get_sz_byte();
//      cont_buf.v_node_idx.clear();
//      cont_buf.v_node_idx.push_back(it_node->get_index() );
    }
  }

  if(accum_byte_sz > 0) {
    // saves the last cont buf
    alive_func_res.add_cont_buf(cont_buf);
//    alive_func_res.v_cont_buf.push_back(cont_buf);
  }
}

void
Liveness::filter_invalid_cont_buf(vector<AliveFunction>& v_liveness)
{
  cout << "filter invalid continuous buffers." << endl;
  cout << "num of alive function calls: " << v_liveness.size() << endl;

  for(auto it_func = v_liveness.begin(); it_func != v_liveness.end(); ++it_func) {
    it_func->rm_cont_buf_less(xt_const::VALID_BUF_LEN);
  }

  vector<AliveFunction> v_swap;
  for(auto it_func = v_liveness.begin(); it_func != v_liveness.end(); ++it_func) {
    // removes empty alive buffer function call if any
    if(!it_func->get_cont_buf().empty() ) {
      v_swap.push_back(*it_func);
    }
  }
  v_liveness.swap(v_swap);
  cout << "num of alive function calls: " << v_liveness.size() << endl;
}

void Liveness::filter_kernel_buf(vector<AliveFunction>& v_liveness_res)
{
  cout << "filter kernel continuous buffer." << endl;
  cout << "num of alive function calls: " << v_liveness_res.size() << endl;

  for(auto it_func = v_liveness_res.begin(); it_func != v_liveness_res.end(); ++it_func) {
    it_func->rm_cont_buf_large_addr(xt_const::KERNEL_BEGIN_ADDR);
  }

  vector<AliveFunction> v_swap;
  for(auto it_func = v_liveness_res.begin(); it_func != v_liveness_res.end(); ++it_func) {
    // removes empty alive buffer function call if any
    if(!it_func->get_cont_buf().empty() ) {
      v_swap.push_back(*it_func);
    }
  }
  v_liveness_res.swap(v_swap);
  cout << "num of alive function calls: " << v_liveness_res.size() << endl;


//  for(auto it_func = v_liveness_res.begin(); it_func != v_liveness_res.end(); ) {
//    // removes empty alive buffer function call if any
//    if(it_func->get_cont_buf().empty() ) {
//      v_liveness_res.erase(it_func);
//    } else {
//      ++it_func;
//    }
//  }
}
