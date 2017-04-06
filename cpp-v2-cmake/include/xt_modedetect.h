// Referenced Cipher Xray's class: ModeDetector
// Currently not used, replaced by xt_blockmodedetector.h

#ifndef XT_MODEDETECT_H_
#define XT_MODEDETECT_H_

#include <memory>
#include <vector>

#include "RangeArray.h"
#include "xt_ByteTaintPropagate.h"

typedef std::shared_ptr<Range> RangeSPtr;
typedef std::shared_ptr<RangeArray> RangeArraySPtr;
typedef std::vector<RangeSPtr> Blocks;
typedef std::vector<RangeArraySPtr> V_Ptr_RangeArray;

class ModeDetect {
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
  unsigned int MIN_ADDRESS = 0x300;
  unsigned int MAX_ADDRESS = 0xc0000000;
  unsigned int WINDOW_SIZE = 64; // 64 bytes
  unsigned int MIN_BUF_SZ = 8;

  enum res_block_idx {  idx_in_block = 0, idx_out_block = 1};

  std::string mode_name;
  int type_enc_dec;

  Range input;
  Range output;

  // Determines if given block cipher is padding or not.
  // 1) Only detects PKCS7 padding and
  // 2) there will be false positive, when if it is enc, the cipher text
  //    happens to be:
  //    01
  //    02 02
  //    03 03 03
  //    etc
  bool is_padding(RangeArraySPtr last_block);
  // Removes ranges smaller than minimum range in the given range array
  void rm_minimum_range(RangeArray &ra, unsigned int minimum_range);
};

class DetectFactory {
 public:
  static DetectFactory &get_instance() { return detect_factory_; }
  static std::vector<ModeDetect *> &get_detectors() { return detectors_; };

  void begin();
  void next() { it_detector++; }
  bool at_end() { return (it_detector == detectors_.end()); }

  void count_num_detector();
  void register_detector(ModeDetect *det);
  ModeDetect *get_detector() { return *it_detector; }

 private:
  static DetectFactory detect_factory_;
  static std::vector<ModeDetect *> detectors_;

  std::vector<ModeDetect *>::iterator it_detector;

  DetectFactory() {};
  ~DetectFactory() {};
  DetectFactory(const DetectFactory&);
  DetectFactory & operator=(const DetectFactory&);
};

class CBCDetect : public ModeDetect {
 public:
  bool analyze_mode(std::vector<ByteTaintPropagate *> &v_in_propagate,
                    Blocks &blocks);
  bool analyze_mode_alter(std::vector<ByteTaintPropagate *> &v_in_propagate,
                          Blocks &blocks,
                          unsigned int out_begin_addr,
                          unsigned int out_len);
  bool analyze_mode_improve(std::vector<ByteTaintPropagate *> &v_in_propagate,
                            Blocks &blocks,
                            unsigned int out_begin_addr,
                            unsigned int out_len);
  static CBCDetect &get_instance() { return cbc_; }

 private:
  static CBCDetect cbc_;
  CBCDetect() { mode_name = "cbc"; }
  ~CBCDetect() {}

  // Finds the begin addr of range of next block
  inline unsigned int get_next_b_begin_addr(RangeArray &ra,
                                            unsigned int addr_byte_to_next_b);
  // Determines if the impact byte to next block's decrypted text buffer,
  // is in order to its byte position in the current block
  inline bool is_in_order_impact(unsigned int addr_to_nex_b_byte,
                                 unsigned int addr_next_b_r_begin,
                                 unsigned int idx_byte);

  bool analyze_enc(std::vector<ByteTaintPropagate *> &v_in_propagate,
                   Blocks &blocks,
                   unsigned int out_addr_begin,
                   unsigned int out_len);
  bool analyze_enc_block(std::vector<ByteTaintPropagate *> &v_in_propagate,
                         Blocks &blocks,
                         bool is_last,
                         unsigned int idx_block,
                         unsigned int out_addr_begin,
                         unsigned int out_len);
  bool analyze_enc_byte(std::vector<ByteTaintPropagate *> &v_in_propagate,
                        Blocks &blocks,
                        unsigned int idx_block,
                        unsigned int idx_byte,
                        unsigned int out_addr_begin,
                        unsigned int out_len);
  // Analyzes if input range array has containing all ranges of
  // output range arrary. The 1 : n pattern in cbc enc
  bool analyze_enc_ra(RangeArray &in_ra, RangeArray &out_ra);
  bool analyze_enc_ra_alter(RangeArray &in_ra, RangeArray &out_ra);

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

  void disp_block(std::vector<ByteTaintPropagate *> &v_in_propagate,
                  Blocks &blocks,
                  unsigned int idx_block,
                  unsigned int out_addr_begin,
                  unsigned int out_len);
  void disp_byte(std::vector<ByteTaintPropagate *> &v_in_propagate,
                 Blocks &blocks,
                 unsigned int idx_block,
                 unsigned int idx_byte,
                 unsigned int out_addr_begin,
                 unsigned int out_len);
  // current block i, next block i + 1. If block i and i+1 are
  // sucessive blocks in cbc dec, their decrypted buffer range
  // should be successive.
  // Get the len of decrypted buffer range in block i+1
  unsigned int get_next_bk_range_len(std::vector<ByteTaintPropagate *> &v_in_propagate,
                                     unsigned int i_1stbyte_curr_bk,
                                     unsigned int i_1stbyte_next_bk,
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

  // If either of range array has range containing a range in other,
  // remove that range in both arraies
  void rm_contain_ranges(RangeArray &ra1, RangeArray &ra2);
  void rm_ident_ranges(RangeArray &ra1, RangeArray &ra2);
};

class ECBDetect : public ModeDetect{
 public:
  static ECBDetect &get_instance() { return ecb_; }

  bool analyze_mode(std::vector<ByteTaintPropagate *> &v_in_propagate,
                    Blocks &blocks);
  bool analyze_ecb_mode(std::vector<ByteTaintPropagate *> &v_in_propa,
                    RangeArray &in_blocks,
                    V_Ptr_RangeArray &out_propa_ra);
 private:


  static ECBDetect ecb_;
  ECBDetect() { mode_name = "ecb"; }
  ~ECBDetect() {}

  V_Ptr_RangeArray v_res_block_; // stores results of block detections

  void analyze_ecb_enc_dec();

  bool analyze_ecb_block(Range &block, RangeArraySPtr block_propa_ra,
                         RangeArray *res_block);
  bool analyze_ecb_last_block(Range &block, uint32_t block_sz,
                              RangeArraySPtr block_propa_ra,
                              RangeArray *res_block);
  // Determines if current result block and previous result block
  // (stores in v_res_block_) is continuous block
  bool is_continuous_block(RangeArray *curr_res_block);
};

#endif /* XT_MODEDETECT_H_ */
