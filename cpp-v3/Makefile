CXX 	  = g++-4.9
CXXFLAG   = -g -std=c++11
LFLAG     = -g -std=c++11
INC	  	  = -Iinclude

DIR_BIN	= ./bin/
DIR_SRC = ./src/
DIR_INC = ./include/
DIR_OBJ = ./build/

DET_OBJ = $(DIR_OBJ)main.o $(DIR_OBJ)xt_util.o

all: $(DIR_BIN)detector

$(DIR_BIN)detector : $(DET_OBJ) 
	$(CXX) -o $@  $^ $(LFLAG) -lboost_program_options

$(DET_OBJ): $(DIR_OBJ)%.o : $(DIR_SRC)%.cpp
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
