#include <string>
#include "xt_flag.h"
#include "xt_log.h"
#include "xt_util.h"

using namespace std;

XTLog::XTLog(vector<string> &vXTLog)
{
	m_vXTLog = vXTLog;

	vector<string>::iterator it = m_vXTLog.begin();
	for(; it != m_vXTLog.end(); ++it){
		XTRecord xtRecord(*it);
		m_vXTRecord.push_back(xtRecord);	
	}
}

XTRecord XTLog::getRecord(std::size_t index)
{
	return m_vXTRecord[index];
}