// This class referenced CipherXray's RangeArray class.

// After byte taint analysis, for each byte of potential
// input buffer, we generates its propagation result,
// which are a series of <byte addr, val>.
// We now merge these single bytes into continuous buffers (ranges)
// for further analysis.

#ifndef RANGEARRAY_H_
#define RANGEARRAY_H_

class Range{
public:
    Range(unsigned int begin_addr, unsigned int len){
        begin_addr_ = begin_addr;
        end_addr_   = begin_addr + len;
    }
    unsigned int set_begin(unsigned int begin_addr) { begin_addr_ = begin_addr; }
    unsigned int get_begin() {return begin_addr_; }
    unsigned int set_end(unsigned int end_addr) { end_addr_ = end_addr; }
    unsigned int get_end() {return end_addr_; }
    unsigned int get_len() {return end_addr_ - begin_addr_; }

private:
    unsigned int begin_addr_;
    unsigned int end_addr_; // end addr is 1 byte pass the last byte
};

class RangeArray{
public:
    RangeArray();
    RangeArray(unsigned int begin_addr, unsigned int len);
    ~RangeArray();

    Range *operator[] (int i) const;
    Range *at(int i) const;

    RangeArray &operator=(const RangeArray &r);

    void add_range(unsigned int begin_addr, unsigned int len);
    void disp_range_array();

    // Result common ranges stores in common
    void get_common_range(RangeArray &ra_right, RangeArray &common);
    RangeArray &get_common_range(RangeArray &r);
    unsigned int get_size() const;
    // Removes ranges given their positions in the range array
    void remove_ranges(int first, int last);
    void remove_range(int pos);
    void reset();

private:
    Range **ref_rray_;
    unsigned int array_size_;
    unsigned int array_used_;

    void copy(const RangeArray &src);
    void init();

    void insert_range(int pos, unsigned int begin_addr, unsigned int len);

};

#endif /* RANGEARRAY_H_ */