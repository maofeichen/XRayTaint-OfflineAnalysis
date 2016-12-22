OBJS = xt_main.o xt_data.o xt_file.o xt_liveness.o \
		xt_preprocess.o xt_propagate.o xt_searchavalanche.o xt_util.o

CC = g++-4.9
INC = -Iinclude
CFLAG = -g -std=c++11

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

.PHONY : clean
clean :
	-rm $(OBJS) ./bin/xt_main