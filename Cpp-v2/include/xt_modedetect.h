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
    bool analyze_mode_alter(std::vector<ByteTaintPropagate *> &v_in_propagate,
                            Blocks &blocks,
                            unsigned int out_begin_addr,
                            unsigned int out_len);
    static CBCDetect &get_instance() { return cbc_;}

private:
    static CBCDetect cbc_;
    CBCDetect() { mode_name = "cbc"; }
    ~CBCDetect() {}

    // Determines if the impact byte to next block's decrypted text buffer,
    // is in order to its byte position in the current block
    inline bool is_in_order_impact(unsigned int addr_to_nex_b_byte,
                                   unsigned int addr_next_b_r_begin,
                                   unsigned int idx_byte);

    bool analyze_enc(std::vector<ByteTaintPropagate *> &v_in_propagate,
                     Blocks &blocks);
    bool analyze_dec(std::vector<ByteTaintPropagate *> &v_in_propagate,
                     Blocks &blocks,
                     unsigned int out_addr_begin,
                     unsigned int out_len);
    bool analyze_dec_block(std::vector<ByteTaintPropagate *> &v_in_propagate,
                           Blocks &blocks,
                           bool is_last,
                           unsigned int idx_block,
                           unsigned int out_addr_begin,
                           unsigned int out_len);
    bool analyze_dec_byte(std::vector<ByteTaintPropagate *> &v_in_propagate,
                          Blocks &blocks,
                          unsigned int idx_byte,
                          unsigned int idx_block,
                          unsigned int out_addr_begin,
                          unsigned int out_len);

    // determines if the byte of current block has 1:1 pattern to
    // next block's decrypted text buffer
    bool has_one_to_one_pattern(std::vector<ByteTaintPropagate *> &v_in_propagate,
                                Blocks &blocks,
                                unsigned int idx_byte,
                                unsigned int idx_block,
                                unsigned int out_addr_begin,
                                unsigned int out_len);
    // if current block's propagate range is successive with the
    // next block's propagate range
    bool is_range_successive(std::vector<ByteTaintPropagate *> &v_in_propagate,
                             Blocks &blocks,
                             unsigned int idx_block,
                             unsigned int out_addr_begin,
                             unsigned int out_len);
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
