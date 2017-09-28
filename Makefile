CFLAGS += -Wall
CFLAGS += -O3
CFLAGS += -std=c++11

ptrace-demo: ptrace_demo.cpp
	$(CXX) -o $@ $(CFLAGS) $<
