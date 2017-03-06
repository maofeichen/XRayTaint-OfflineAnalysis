// This class is used to detect blocks, modes after liveness
// analysis.

#ifndef XT_DETECT_H_
#define XT_DETECT_H_

#include "xt_log.h"

#include <vector>

class Detect{
public:
    Detect(std::vector<t_AliveFunctionCall> v_func_cont_buf,
		   XTLog &xt_log);

    void detect_cipher();
private:
    XTLog xt_log_;
	std::vector<t_AliveFunctionCall> v_func_cont_buf_;

	void detect_cipher_in_out(t_AliveContinueBuffer &in,
	                          t_AliveContinueBuffer &out);
};

#endif /* XT_DETECT_H_ */
