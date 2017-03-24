#ifndef XT_DETECTOR_H
#define XT_DETECTOR_H

#include <string>

class Detector{
 public:
  Detector(std::string fn, bool dump);
  void detect();

 private:
  std::string fn_;
  bool dump_ = false;

  std::string get_time();
};

#endif //XT_DETECTOR_H
