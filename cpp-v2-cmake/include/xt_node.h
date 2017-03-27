#ifndef XT_NODE_H
#define XT_NODE_H

#include <string>
#include <vector>

class XTNode
 {
 private:
 	bool m_isMark;
 	unsigned int m_index = 0;

 	std::string m_flag;
 	std::string m_addr;
 	std::string m_val;

 	unsigned int m_intAddr = 0;
 	unsigned int m_bitSize = 0;
 
 public:
 	XTNode();
 	XTNode(std::vector<std::string> &str_vNode, bool isSrc);
 	XTNode(std::vector<std::string> &node, bool isSrc, unsigned int index);
 
 	bool isMark();
 	unsigned int getIndex();	
 	std::string getFlag();
 	std::string getAddr();
 	std::string getVal();
 	unsigned int getIntAddr();
 	unsigned int getBitSize();
 	unsigned int getByteSize();	
 }; 
#endif