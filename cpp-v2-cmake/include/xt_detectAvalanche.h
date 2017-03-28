#ifndef XT_DETECTAVALANCHE
#define XT_DETECTAVALANCHE

class XT_DetectAvalanche {
 public:
  XT_DetectAvalanche();
  XT_DetectAvalanche(bool isAddInputBuffer,
					 std::string funcCallMark,
					 unsigned int beginAddress,
					 unsigned int size);

  void detect_avalanche(std::string logPath, bool is_dump);
 private:
  bool m_isAddInputBuffer;

  std::string m_funcCallMark;
  unsigned int m_beginAddress;
  unsigned int m_size;

  std::string get_time();

};
#endif
