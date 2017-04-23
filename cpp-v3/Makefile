CXX 	  = g++-4.9
CXXFLAG   = -O0 -Wall -g -std=c++11
LD		  = g++-4.9
LFLAG     = 
INC	  	  = -Iinclude

DIR_BIN	= ./bin/
DIR_SRC = ./src/
DIR_INC = ./include/
DIR_OBJ = ./build/

DET_OBJ = $(DIR_OBJ)main.o \
		  $(DIR_OBJ)xt_util.o $(DIR_OBJ)xt_detector.o \
		  $(DIR_OBJ)xt_file.o $(DIR_OBJ)xt_preprocess.o \
		  $(DIR_OBJ)xt_log.o $(DIR_OBJ)xt_record.o $(DIR_OBJ)xt_node.o \
		  $(DIR_OBJ)xt_contbuf.o $(DIR_OBJ)xt_alivefunc.o \
		  $(DIR_OBJ)xt_liveness.o \
		  $(DIR_OBJ)xt_avalanche.o \
		  $(DIR_OBJ)xt_propagate.o \
		  $(DIR_OBJ)TaintBitMap.o \
		  $(DIR_OBJ)xt_range.o $(DIR_OBJ)xt_rangearray.o \
		  $(DIR_OBJ)xt_taintpropagate.o \
		  $(DIR_OBJ)xt_blockdetector.o

all: $(DIR_BIN)detector

$(DIR_BIN)detector : $(DET_OBJ)
	@echo "Linking: "$@ 
	$(LD) -o $@  $^ $(LFLAG) -lboost_program_options

$(DET_OBJ): $(DIR_OBJ)%.o : $(DIR_SRC)%.cpp
	@echo "Compiling: "$<
	$(CXX) $(INC) -c $< $(CXXFLAG) -MMD -MP -o $@

-include $(DIR_OBJ)%.d	
#$(DIR_OBJ)main.o : $(DIR_SRC)main.cpp
#	$(CXX) -c $^ $(CXXFLAG) -o $@
#
#$(DIR_OBJ)util.o : $(DIR_SRC)xt_util.cpp
#	$(CXX) $(INC) -c $^ $(CXXFLAG) -o $@
	
.PHONY : clean
clean :
	-rm $(DIR_OBJ)*.o $(DIR_OBJ)*.d $(DIR_BIN)detector
