#include "xt_modedetect.h"

using namespace std;

int ModeDetect::TYPE_UNDEF = 0;
int ModeDetect::TYPE_ENC   = 1;
int ModeDetect::TYPE_DEC   = 2;

ModeDetect::ModeDetect()
{
    DetectFactory::get_instance().register_detector(this);
    type_enc_dec = TYPE_UNDEF;
}

ModeDetect::~ModeDetect() {}

CBCDetect CBCDetect::cbc;

bool CBCDetect::analyze_mode(vector<ByteTaintPropagate *> &v_in_propagate,
                             Blocks &blocks)
{
    return false;
}

DetectFactory DetectFactory::detect_factory_;
std::vector<ModeDetect *> DetectFactory::detectors;
