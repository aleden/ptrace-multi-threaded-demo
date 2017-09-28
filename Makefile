CFLAGS += -Wall
CFLAGS += -O3
CFLAGS += -std=c++11

ptrace-multi-threaded-demo: ptrace_multi_threaded_demo.cpp
	$(CXX) -o $@ $(CFLAGS) $<
