ptrace-demo: ptrace_demo.cpp
	g++ -o $@ -Wall -O3 -std=c++11 $< -pthread
