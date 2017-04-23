#ifndef XT_CONSTANT_H_
#define XT_CONSTANT_H_

#include <stdint.h>

namespace xt_const
{
const uint32_t STACK_BEGIN_ADDR   = 0xb0000000;
const uint32_t VALID_BUF_LEN      = 0x8;
const uint32_t KERNEL_BEGIN_ADDR  = 0xC0000000;

// search propagation
const uint32_t BYTE_VAL_STR_LEN   = 2;
}



#endif /* XT_CONSTANT_H_ */
