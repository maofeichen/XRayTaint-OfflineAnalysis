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
