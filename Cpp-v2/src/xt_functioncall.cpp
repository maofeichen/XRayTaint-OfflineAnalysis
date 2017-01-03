#include "xt_functioncall.h"

using namespace std;

XT_FunctionCall::XT_FunctionCall() {}

string XT_FunctionCall::getFirstCallMark() {return m_callMarkFirst; }

string XT_FunctionCall::getSecondCallMark() {return m_callMarkSecond; }

string XT_FunctionCall::getFirstRetMark() {return m_retMarkFirst; }

string XT_FunctionCall::getSecondRetMark() {return m_retMarkSecond; }

std::vector<XT_AliveBuffer> XT_FunctionCall::getAliveBuffers() {return m_vAliveBuffer; }	