#ifndef XT_FLAG_H
#define XT_FLAG_H

#include <string>

namespace flag 
{
const std::string XT_SIZE_BEGIN          = "20";
const std::string XT_SIZE_END            = "24";

const std::string XT_INSN_ADDR           = "32";
const std::string XT_TCG_DEPOSIT         = "4a";

const std::string XT_CALL_INSN           = "14";
const std::string XT_CALL_INSN_SEC       = "15";
const std::string XT_CALL_INSN_FF2       = "1a";
const std::string XT_CALL_INSN_FF2_SEC   = "1b";

const std::string XT_RET_INSN            = "18";
const std::string XT_RET_INSN_SEC        = "19";

const std::string TCG_QEMU_LD            = "52";
const std::string TCG_QEMU_LD_POINTER	   = "56";
const std::string TCG_QEMU_ST            = "5a";
const std::string TCG_QEMU_ST_POINTER	   = "5e";

const int NUM_TCG_LD			               = 0x52;
const int NUM_TCG_LD_POINTER	           = 0x56;
const int NUM_TCG_ST			               = 0x5a;
const int NUM_TCG_ST_POINTER	           = 0x5e;

const int NUM_TCG_LD_MIN		             = 0x52;
const int NUM_TCG_ST_MAX		             = 0x61;

const std::string TCG_ADD                = "3b";
const std::string TCG_XOR                = "47";

const int G_TEMP_UNKNOWN        = 0xfff0;
const int G_TEMP_ENV            = 0xfff1;
const int G_TEMP_CC_OP          = 0xfff2;
const int G_TEMP_CC_SRC         = 0xfff3;
const int G_TEMP_CC_DST         = 0xfff4;
const int G_TEMP_CC_TMP         = 0xfff5;
const int G_TEMP_EAX            = 0xfff6;
const int G_TEMP_ECX            = 0xfff7;
const int G_TEMP_EDX            = 0xfff8;
const int G_TEMP_EBX            = 0xfff9;
const int G_TEMP_ESP            = 0xfffa;
const int G_TEMP_EBP            = 0xfffb;
const int G_TEMP_ESI            = 0xfffc;
const int G_TEMP_EDI            = 0xfffd;

enum Mem_Type{
  M_LOAD,
  M_LOAD_PTR,
  M_STORE,
  M_STORE_PTR,
  M_UNKNOW
};
}

#endif //XT_FLAG_H
