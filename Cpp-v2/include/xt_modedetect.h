// Referenced Cipher Xray's class: ModeDetector

#ifndef XT_MODEDETECT_H_
#define XT_MODEDETECT_H_

#include <memory>
#include <vector>

#include "RangeArray.h"
#include "xt_ByteTaintPropagate.h"

typedef std::shared_ptr<Range> RangeSPtr;
typedef std::vector<RangeSPtr> Blocks;

class ModeDetect{
public:
    static int TYPE_UNDEF;
    static int TYPE_ENC;
    static int TYPE_DEC;

    ModeDetect();
    virtual ~ModeDetect() = 0;

    std::string &get_mode_name() { return mode_name; }

    virtual bool analyze_mode(std::vector<ByteTaintPropagate *> &v_in_propagate,
                              Blocks &blocks) = 0;
protected:
    std::string mode_name;
    int type_enc_dec;

private:
};

class CBCDetect : public ModeDetect{
public:
    bool analyze_mode(std::vector<ByteTaintPropagate *> &v_in_propagate,
                      Blocks &blocks);
private:
    static CBCDetect cbc;
    CBCDetect() { mode_name = "cbc"; }
    ~CBCDetect() {}
};

class DetectFactory{
public:
    static DetectFactory &get_instance() { return detect_factory_; }

    void begin() { it_detector = detectors.begin(); }
    void next()  { it_detector++; }
    bool at_end() { return ( it_detector == detectors.end() ); }

    void register_detector(ModeDetect *det) { detectors.push_back(det); }
    ModeDetect *get_detector() { return *it_detector; }

private:
    static DetectFactory detect_factory_;
    static std::vector<ModeDetect *> detectors;

    std::vector<ModeDetect *>::iterator it_detector;

    DetectFactory() {};
    ~DetectFactory() {};
};

#endif /* XT_MODEDETECT_H_ */
