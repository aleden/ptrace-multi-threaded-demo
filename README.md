# ptrace-multi-threaded-demo
Simple commented program which demonstrates using ptrace(2)

This is no longer maintained; see ptracetricks: https://github.com/aleden/ptracetricks

## Usage
```bash
cd ptrace-multi-threaded-demo
make
./ptrace-multi-threaded-demo 1> stdout 2> stderr
```
In another terminal, do
```bash
cd ptrace-multi-threaded-demo
tail --follow stdout
```
to follow output from the children and
```bash
cd ptrace-multi-threaded-demo
tail --follow stderr
```
to follow output from the parent. You should see output like the following:
```
parent: forking...
parent: setting ptrace options...
ptrace options set!
parent: [3025] SYSCALL [rt_sigprocmask] = 0
parent: [3025] SYSCALL [UNKNOWN] = 811208704
parent: [3025] SYSCALL [mprotect] = 0
parent: thread 3026 created...
parent: [3025] SYSCALL [clone] = 3026
parent: [3025] SYSCALL [UNKNOWN] = 802816000
parent: [3026] SYSCALL [set_robust_list] = 0
parent: [3025] SYSCALL [mprotect] = 0
parent: [3026] SYSCALL [gettid] = 3026
parent: thread 3027 created...
parent: [3025] SYSCALL [clone] = 3027
parent: [3025] SYSCALL [UNKNOWN] = 794423296
parent: [3025] SYSCALL [mprotect] = 0
parent: [3027] SYSCALL [set_robust_list] = 0
parent: [3026] SYSCALL [fstat] = 0
parent: thread 3028 created...
parent: [3025] SYSCALL [clone] = 3028
parent: [3026] SYSCALL [UNKNOWN] = 660205568
parent: [3026] SYSCALL [munmap] = 0
parent: [3028] SYSCALL [set_robust_list] = 0
parent: [3026] SYSCALL [munmap] = 0
parent: [3026] SYSCALL [mprotect] = 0
parent: [3026] SYSCALL [write] = 16
parent: [3027] SYSCALL [futex] = 0
parent: [3026] SYSCALL [futex] = 1
parent: [3027] SYSCALL [gettid] = 3027
parent: [3027] SYSCALL [write] = 16
parent: [3028] SYSCALL [futex] = 0
parent: [3027] SYSCALL [futex] = 1
parent: [3028] SYSCALL [gettid] = 3028
parent: [3028] SYSCALL [write] = 16
parent: [3028] SYSCALL [futex] = 0
parent: [3026] SYSCALL [clock_nanosleep] = 0
parent: [3027] SYSCALL [clock_nanosleep] = 0
parent: [3028] SYSCALL [clock_nanosleep] = 0
parent: [3026] SYSCALL [gettid] = 3026
parent: [3026] SYSCALL [write] = 16
parent: [3027] SYSCALL [futex] = 0
parent: [3026] SYSCALL [futex] = 1
parent: [3027] SYSCALL [gettid] = 3027
parent: [3027] SYSCALL [write] = 16
parent: [3028] SYSCALL [futex] = 0
parent: [3027] SYSCALL [futex] = 1
parent: [3028] SYSCALL [gettid] = 3028
parent: [3028] SYSCALL [write] = 16
parent: [3028] SYSCALL [futex] = 0
...
```
```
child: 1 [3026]
child: 1 [3027]
child: 1 [3028]
child: 2 [3026]
child: 2 [3027]
child: 2 [3028]
...
```
