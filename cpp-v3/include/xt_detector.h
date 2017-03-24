#ifndef XT_DETECTOR_H
#define XT_DETECTOR_H

class Detector{
 public:
  Detector(string fn, bool dump);
  void detect();

 private:
  string fn_;
  bool dump_;
};

#endif //XT_DETECTOR_H
