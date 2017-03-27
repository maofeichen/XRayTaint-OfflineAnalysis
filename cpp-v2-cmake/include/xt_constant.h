#ifndef XT_CONTANT_H
#define XT_CONTANT_H

#include <string> 

// Taint Input Buffer
const std::string TAINT_FUNC_CALL_MARK = "14\tbffff4dc\t804a059\t";
const unsigned long TAINT_BUF_BEGIN_ADDR = 0xbffff764; 
const unsigned long TAINT_BUF_SIZE = 128;

// Taint Key Buf
// const std::string TAINT_FUNC_CALL_MARK		= "14\tbffff4dc\t80487e5\t";
// const unsigned long TAINT_BUF_BEGIN_ADDR 	= 0xbffff78c;
// const unsigned long TAINT_BUF_SIZE 			= 128;

const unsigned int BIT_TO_BYTE 		= 8;
const unsigned int VALID_BYTE_SIZE 	= 8;
const unsigned long KERNEL_ADDRESS	= 0xC0000000;
#endif