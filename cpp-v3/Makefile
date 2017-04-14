CC 	  = g++-4.9
CFLAG = -g -std=c++11
LFLAG = -g -std=c++11
INC	  = -Iinclude

DIR_BIN	= ./bin/
DIR_SRC = ./src/
DIR_INC = ./include/
DIR_OBJ = ./build/

DET_OBJ = $(DIR_OBJ)main.o $(DIR_OBJ)util.o

all: detector

detector : $(DET_OBJ) 
	$(CC) -o $(DIR_BIN)detector  $(DET_OBJ) $(LFLAG) -lboost_program_options
	
$(DIR_OBJ)main.o : $(DIR_SRC)main.cpp
	$(CC) -c $(DIR_SRC)main.cpp $(CFLAG) -o $(DIR_OBJ)main.o

$(DIR_OBJ)util.o : $(DIR_SRC)xt_util.cpp
	$(CC) $(INC) -c $(DIR_SRC)xt_util.cpp $(CFLAG) -o $(DIR_OBJ)util.o
	
.PHONY : clean
clean :
	-rm $(DIR_OBJ)*.o $(DIR_BIN)detector
