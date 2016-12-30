#ifndef XT_NODE_H
#define XT_NODE_H

#include <string>

class XTNode
 {
 private:
 	bool m_isMark;
 	std::string m_flag;
 	std::string m_addr;
 	std::string m_val;

 	unsigned int m_intAddr;
 	unsigned int m_bitSize;
 public:
 	XTNode();
 
 	bool isMark();	
 	std::string getFlag();
 	std::string getAddr();
 	std::string getVal();
 	unsigned int getIntAddr();
 	unsigned int getBitSize();	
 }; 
#endif