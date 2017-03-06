OBJS = xt_main.o xt_data.o xt_file.o xt_liveness.o \
		xt_preprocess.o xt_propagate.o xt_searchavalanche.o \
		xt_util.o xt_detectAvalanche.o xt_log.o xt_taintpropagate.o \
		xt_node.o xt_record.o xt_alivebuffer.o xt_functioncall.o \
		TaintBitMap.o xt_detect.o

OBJS_SRCH_PROPAGATE = xt_search_propagate.o xt_util.o xt_file.o xt_liveness.o \
					  xt_searchavalanche.o xt_node.o xt_functioncall.o xt_log.o \
					  xt_propagate.o xt_alivebuffer.o TaintBitMap.o xt_record.o \
					  xt_taintpropagate.o xt_preprocess.o

CC = g++-4.9
INC = -Iinclude
CFLAG = -g -std=c++11

all : xt_main xt_search_propagate

xt_search_propagate : $(OBJS_SRCH_PROPAGATE) 
	$(CC) $(INC) -o ./bin/xt_search_propagate $(OBJS_SRCH_PROPAGATE) $(CFLAG) -lboost_program_options
	
xt_search_propagate.o : src/xt_search_propagate.cpp
	$(CC) $(INC) -c src/xt_search_propagate.cpp $(CFLAG)

xt_main : $(OBJS)
	$(CC) $(INC) -o ./bin/xt_main $(OBJS) $(CFLAG) -lboost_program_options 

xt_main.o : src/xt_main.cpp
	$(CC) $(INC) -c src/xt_main.cpp $(CFLAG)

xt_data.o : src/xt_data.cpp
	$(CC) $(INC) -c src/xt_data.cpp $(CFLAG)

xt_file.o : src/xt_file.cpp
	$(CC) $(INC) -c src/xt_file.cpp $(CFLAG)

xt_liveness.o : src/xt_liveness.cpp
	$(CC) $(INC) -c src/xt_liveness.cpp $(CFLAG)

xt_preprocess.o : src/xt_preprocess.cpp
	$(CC) $(INC) -c src/xt_preprocess.cpp $(CFLAG)

xt_propagate.o : src/xt_propagate.cpp
	$(CC) $(INC) -c src/xt_propagate.cpp $(CFLAG)

xt_searchavalanche.o : src/xt_searchavalanche.cpp
	$(CC) $(INC) -c src/xt_searchavalanche.cpp $(CFLAG)

xt_util.o : src/xt_util.cpp
	$(CC) $(INC) -c src/xt_util.cpp $(CFLAG)

xt_detectAvalanche.o : src/xt_detectAvalanche.cpp
	$(CC) $(INC) -c src/xt_detectAvalanche.cpp $(CFLAG)

xt_log.o : src/xt_log.cpp
	$(CC) $(INC) -c src/xt_log.cpp $(CFLAG)

xt_taintpropagate.o : src/xt_taintpropagate.cpp
	$(CC) $(INC) -c src/xt_taintpropagate.cpp $(CFLAG)

xt_node.o : src/xt_node.cpp
	$(CC) $(INC) -c src/xt_node.cpp $(CFLAG)

xt_record.o : src/xt_record.cpp
	$(CC) $(INC) -c src/xt_record.cpp $(CFLAG)

xt_alivebuffer.o : src/xt_alivebuffer.cpp
	$(CC) $(INC) -c src/xt_alivebuffer.cpp $(CFLAG)

xt_functioncall.o : src/xt_functioncall.cpp
	$(CC) $(INC) -c src/xt_functioncall.cpp $(CFLAG)

TaintBitMap.o : src/TaintBitMap.cpp
	$(CC) $(INC) -c src/TaintBitMap.cpp $(CFLAG)

xt_detect.o : src/xt_detect.cpp
	$(CC) $(INC) -c src/xt_detect.cpp $(CFLAG)

.PHONY : clean
clean :
	-rm $(OBJS) ./bin/xt_main