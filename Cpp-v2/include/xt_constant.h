#ifndef XT_CONTANT_H
#define XT_CONTANT_H

#include <string> 

// Taint Input Buffer
// const std::string TAINT_FUNC_CALL_MARK = "14\tbffff4dc\t804a059\t";
// Taint Key Buf
const std::string TAINT_FUNC_CALL_MARK = "14\tbffff4fc\t804873b\t";
const unsigned long TAINT_BUF_BEGIN_ADDR = 0xbffff754;
const unsigned long TAINT_BUF_SIZE = 128;

#endif