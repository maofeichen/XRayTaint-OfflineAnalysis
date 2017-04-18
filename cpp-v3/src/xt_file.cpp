#include "xt_file.h"

#include <fstream>
#include <iostream>

using namespace std;

xt_file::File::File(string fn) {
  fn_ = fn;
}

void xt_file::File::read(std::vector<std::string> &s_log) {
  string lp = xt_file::log_path + fn_ + xt_file::ext;
  cout << "reading log file... : " << lp  << endl;

  ifstream fp(lp.c_str() );

  if(fp.is_open() ) {
    string line;
    while (getline(fp, line) ) {
      s_log.push_back(line);
    }
  } else {
    cout << "error open file: " << lp << endl;
  }
  fp.close();

  //  for(auto it = v.begin(); it != v.end(); ++it) {
  //    cout << *it << endl;
  //  }
}

void xt_file::File::write_str_log(const string path,
                                  const vector<string> &v_s_log) {
  if(v_s_log.empty() ) {
    cout << "write log: log is empty" << endl;
    return;
  }

  cout << "write log path: " << path << endl;

  ofstream fp(path.c_str() );
  if(fp.is_open() ) {
    for(auto it = v_s_log.begin(); it != v_s_log.end(); ++it) {
      fp << *it << '\n';
    }

    fp.close();
  }else {
    cout << "error: write log - can't open file" << endl;
  }
}

void xt_file::File::write_log_mem(const string path,
                                  const Log &log)
{
  if(log.get_size() == 0) {
    cout << "write log: log is empty" << endl;
    return;
  }

  cout << "write log to: " << path << endl;
  ofstream fp(path.c_str() );
  if(fp.is_open() ) {
    for (auto it = log.get_log().begin(); it != log.get_log().end(); ++it) {
      if (it->is_makr()) {
        fp << it->get_const_src_node().get_flag() << '\t'\
           << it->get_const_src_node().get_addr() << '\t'\
           << it->get_const_src_node().get_val()  << '\t' << '\n';
      } else {
        fp << it->get_const_src_node().get_flag() << '\t'\
           << it->get_const_src_node().get_addr() << '\t'\
           << it->get_const_src_node().get_val()  << '\t';

        fp << it->get_const_dst_node().get_flag() << '\t'\
           << it->get_const_dst_node().get_addr() << '\t'\
           << it->get_const_dst_node().get_val()  << '\t';
        if (it->get_const_dst_node().is_mem()) {
          fp << it->get_const_dst_node().get_sz_bit() << '\t' << '\n';
        } else if(it->get_const_src_node().is_mem() ) {
          fp << it->get_const_src_node().get_sz_bit() << '\t' << '\n';
        } else {
          fp << '\n';
        }
      }
    }
    fp.close();
  } else {
    cout << "error: write log - can't open file." << endl;
  }
}

void xt_file::File::write_log_idx(const string path,
                                  const Log &log)
{
  if(log.get_size() == 0) {
    cout << "write log: log is empty" << endl;
    return;
  }

  cout << "write log to: " << path << endl;
  ofstream fp(path.c_str() );
  if(fp.is_open() ) {
    for (auto it = log.get_log().begin(); it != log.get_log().end(); ++it) {
      if (it->is_makr()) {
        fp << it->get_const_src_node().get_flag() << '\t'\
           << it->get_const_src_node().get_addr() << '\t'\
           << it->get_const_src_node().get_val()  << '\t'\
           << dec << it->get_index() << '\n';
      } else {
        fp << it->get_const_src_node().get_flag() << '\t'\
           << it->get_const_src_node().get_addr() << '\t'\
           << it->get_const_src_node().get_val()  << '\t';

        fp << it->get_const_dst_node().get_flag() << '\t'\
           << it->get_const_dst_node().get_addr() << '\t'\
           << it->get_const_dst_node().get_val()  << '\t'\
           << dec << it->get_index() << '\n';
      }
    }
    fp.close();
  } else {
    cout << "error: write log - can't open file." << endl;
  }

}

void
xt_file::File::write_alive_func(const string& curr_t,
                                const std::vector< std::vector<Record> >& alive_func) const
{
  if(alive_func.empty() ) {
    cout << "write log: alive buf is empty." << endl;
    return;
  }

  string path = xt_file::res_path
                + fn_
                + xt_file::alive_buf
                + curr_t
                + xt_file::ext;

  cout << "write log to: " << path << endl;
  ofstream fp(path.c_str() );
  if(fp.is_open() ) {
    for(auto it_func = alive_func.begin(); it_func != alive_func.end(); ++it_func) {
      fp << "---------- ----------" << endl;
      fp << it_func->begin()->get_const_src_node().get_flag() << '\t' \
         << it_func->begin()->get_const_src_node().get_addr() << '\t' \
         << it_func->begin()->get_const_src_node().get_val()  << '\t' \
         << dec << it_func->begin()->get_index() << endl;

      fp << (it_func->begin()+1)->get_const_src_node().get_flag() << '\t' \
         << (it_func->begin()+1)->get_const_src_node().get_addr() << '\t' \
         << (it_func->begin()+1)->get_const_src_node().get_val()  << '\t' \
         << dec << (it_func->begin()+1)->get_index() << endl;

      for(auto it_rec = it_func->begin()+2; it_rec != it_func->end()-2; ++it_rec) {
        if(it_rec->get_mem_type() == flag::M_LOAD) {
          fp << it_rec->get_const_src_node().get_flag() << '\t'\
             << it_rec->get_const_src_node().get_addr() << '\t'\
             << it_rec->get_const_src_node().get_val()  << '\t'\
             << it_rec->get_const_dst_node().get_flag() << '\t'\
             << it_rec->get_const_dst_node().get_addr() << '\t'\
             << it_rec->get_const_dst_node().get_val()  << '\t'\
             << dec << it_rec->get_const_src_node().get_sz_bit() << '\t'\
             << dec << it_rec->get_index() << endl;
        }else if(it_rec->get_mem_type() == flag::M_STORE) {
          fp << it_rec->get_const_src_node().get_flag() << '\t'\
             << it_rec->get_const_src_node().get_addr() << '\t'\
             << it_rec->get_const_src_node().get_val()  << '\t'\
             << it_rec->get_const_dst_node().get_flag() << '\t'\
             << it_rec->get_const_dst_node().get_addr() << '\t'\
             << it_rec->get_const_dst_node().get_val()  << '\t'\
             << dec << it_rec->get_const_dst_node().get_sz_bit() << '\t'\
             << dec << it_rec->get_index() << endl;
        }
      }

      fp << (it_func->end()-2)->get_const_src_node().get_flag() << '\t'
         << (it_func->end()-2)->get_const_src_node().get_addr() << '\t'
         << (it_func->end()-2)->get_const_src_node().get_val() << '\t'
         << dec << (it_func->end()-2)->get_index() << endl;

      fp << (it_func->end()-1)->get_const_src_node().get_flag() << '\t'
         << (it_func->end()-1)->get_const_src_node().get_addr() << '\t'
         << (it_func->end()-1)->get_const_src_node().get_val() << '\t'
         << dec << (it_func->end()-1)->get_index() << endl;
    }
    fp.close();
  } else {
     cout << "error: write log - can't open file." << endl;
  }
}

void
xt_file::File::write_cont_buf(const std::string& curr_t,
                              const std::vector<AliveFunction>& v_liveness_res)
{
  if(v_liveness_res.empty() ) {
    cout << "write continuous buffer: given liveness analysis is empty." << endl;
    return;
  }

  string path = xt_file::res_path
                + fn_
                + xt_file::continue_buf
                + curr_t
                + xt_file::ext;
  cout << "write continuous buffers to: " << path << endl;
  ofstream fp(path.c_str() );
  if(fp.is_open() ) {
    for(auto it_func = v_liveness_res.begin(); it_func != v_liveness_res.end(); ++it_func) {
      fp << "Function Call: " << endl;
      fp << it_func->get_fir_c_mark().get_flag() << '\t'
         << it_func->get_fir_c_mark().get_addr() << '\t'
         << it_func->get_fir_c_mark().get_val()  <<  endl;
      fp << it_func->get_sec_c_mark().get_flag() << '\t'
         << it_func->get_sec_c_mark().get_addr() << '\t'
         << it_func->get_sec_c_mark().get_val()  <<  endl;

      for(auto it_buf = it_func->get_cont_buf().begin();
          it_buf != it_func->get_cont_buf().end(); ++it_buf) {
        fp << "Begin_Addr: " << hex << it_buf->get_begin()   << endl;
        fp << "Size: "       << dec << it_buf->get_byte_sz() << " bytes" << endl;
      }

      fp << it_func->get_fir_r_mark().get_flag() << '\t'
         << it_func->get_fir_r_mark().get_addr() << '\t'
         << it_func->get_fir_r_mark().get_val()  <<  endl;
      fp << it_func->get_sec_r_mark().get_flag() << '\t'
         << it_func->get_sec_r_mark().get_addr() << '\t'
         << it_func->get_sec_r_mark().get_val()  <<  endl;
    }
  } else {
    cout << "error: write log - can't open file." << endl;
  }
}
