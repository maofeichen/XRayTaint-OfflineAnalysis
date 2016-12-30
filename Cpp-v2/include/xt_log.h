#ifndef XT_LOG_H
#define XT_LOG_H

#include "xt_data.h"

// ADT for xray taint log

class XTLog
 {
 private:
 	std::vector<std::string> m_vXTLog;

 	Node convertToNode(std::vector<std::string> &recordField, bool isSource);
 public:
	XTLog(std::vector<std::string> &vXTLog);

 	Node getSourceNode(std::size_t index);
 	Node getDestinateNode(std::size_t index);
 	Record getRecord(std::size_t index);
 }; 
#endif