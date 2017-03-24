#include "xt_file.h"

#include <fstream>
#include <iostream>

using namespace std;

xt_file::File::File(string fn) {
  fn_ = fn;
}

vector<string> xt_file::File::read() {
  vector<string> v;
  string lp = xt_file::log_path + fn_ + xt_file::ext;
  cout << "reading log file... : " << lp  << endl;

  ifstream fp(lp.c_str() );

  if(fp.is_open() ) {
    string line;
    while (getline(fp, line) ) {
      v.push_back(line);
    }
  } else {
    cout << "error open file: " << lp << endl;
  }
  fp.close();

  //  for(auto it = v.begin(); it != v.end(); ++it) {
  //    cout << *it << endl;
  //  }

  return v;
}
