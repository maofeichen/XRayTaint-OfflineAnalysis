#ifndef XT_LOG_H
#define XT_LOG_H

#include "xt_record.h"
#include "xt_data.h"

// ADT for xray taint log

class XTLog
{
public:
	XTLog();
	XTLog(std::vector<std::string> &vXTLog);

	XTRecord getRecord(std::size_t index);
	unsigned int findRecord(std::string &s_record);	
	unsigned int getRecordSize();

private:
	// std::vector<std::string> m_vXTLog;
	std::vector<XTRecord> m_vXTRecord;
}; 
#endif