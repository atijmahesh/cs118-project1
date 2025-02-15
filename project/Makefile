CXX=g++
CPPFLAGS=-Wall -Wextra 
LDFLAGS= 
LDLIBS=

SRCS := $(wildcard *.cpp)
EXCL_SRCS := server.cpp client.cpp
PRE_DEPS := $(filter-out $(EXCL_SRCS), $(SRCS))
DEPS=$(PRE_DEPS:%.cpp=%.o)

all: server client 

server: server.o $(DEPS)
client: client.o $(DEPS)

clean:
	@rm -rf server client *.bin *.o

