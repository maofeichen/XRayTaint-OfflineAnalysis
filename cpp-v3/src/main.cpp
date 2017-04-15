#include "boost/program_options.hpp"

#include "xt_detector.h"
#include "xt_util.h"

using namespace boost;
namespace po = boost::program_options;

using namespace std;

int main(int argc, char *argv[]) {
  po::options_description desc("Allowed options");

  desc.add_options()
      ("help,h", "produce help message")
      ("input-file,i", po::value< string >(), "input file: file path")
      ("dump-result,d", po::value< bool >(), "dump result: yes/no, 1/0")
      ;

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help")) {
    cout << desc << endl;
    return 1;
  }

  if(vm.count("input-file") &&
      vm.count("dump-result") ){
    string fp = vm["input-file"].as< string >();
    cout << "input log: " << fp << endl;

    vector<string> v_fp = util::split(fp.c_str(), '/');
    string log_name = v_fp.back();
    log_name = log_name.substr(0, log_name.size() - 4);
    cout << "log name: " << log_name << endl;

    bool is_dump = vm["dump-result"].as< bool >();
    cout << "is dump result: " << is_dump << endl;

    Detector det(log_name, is_dump);
    det.detect();
  }

  return 0;
}
