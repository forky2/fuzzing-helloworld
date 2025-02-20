# AFL++ QEMU persistent mode

## Persistent mode

Confirm where QEMU places the executable:

```
$ AFL_QEMU_DEBUG_MAPS=1 extern/AFLplusplus/afl-qemu-trace targets/vuln_prog_slowinit
4000000000-4000001000 r--p 00000000 fd:00 49571961                       /workspaces/helloworld/targets/vuln_prog_slowinit
4000001000-4000002000 r-xp 00001000 fd:00 49571961                       /workspaces/helloworld/targets/vuln_prog_slowinit
4000002000-4000003000 r--p 00002000 fd:00 49571961                       /workspaces/helloworld/targets/vuln_prog_slowinit
4000003000-4000004000 r--p 00002000 fd:00 49571961                       /workspaces/helloworld/targets/vuln_prog_slowinit
4000004000-4000005000 rw-p 00003000 fd:00 49571961                       /workspaces/helloworld/targets/vuln_prog_slowinit
4001005000-4001006000 ---p 00000000 00:00 0                              
4001006000-4001806000 rw-p 00000000 00:00 0                              [stack]
4001806000-4001807000 r--p 00000000 00:78 90768918                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
4001807000-4001832000 r-xp 00001000 00:78 90768918                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
4001832000-400183c000 r--p 0002c000 00:78 90768918                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
400183c000-400183e000 r--p 00036000 00:78 90768918                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
400183e000-4001840000 rw-p 00038000 00:78 90768918                       /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
4001840000-4001842000 rw-p 00000000 00:00 0                              
400184c000-4001874000 r--p 00000000 00:78 90768921                       /usr/lib/x86_64-linux-gnu/libc.so.6
4001874000-40019fc000 r-xp 00028000 00:78 90768921                       /usr/lib/x86_64-linux-gnu/libc.so.6
40019fc000-4001a4b000 r--p 001b0000 00:78 90768921                       /usr/lib/x86_64-linux-gnu/libc.so.6
4001a4b000-4001a4f000 r--p 001fe000 00:78 90768921                       /usr/lib/x86_64-linux-gnu/libc.so.6
4001a4f000-4001a51000 rw-p 00202000 00:78 90768921                       /usr/lib/x86_64-linux-gnu/libc.so.6
4001a51000-4001a60000 rw-p 00000000 00:00 0                              
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

Check the location of where to defer forkserver to (ostensibly, this must be on
a basic block?); we will use this as both the ENTRYPOINT _and_ the loop START
address:
```
$ objdump -M intel -d targets/vuln_prog_slowinit
...
0000000000001180 <main>:
...
    11f0:       c3                      ret
    -->>11f1:       48 8b 7d 08             mov    rdi,QWORD PTR [rbp+0x8]
    11f5:       48 8d 35 6f 0e 00 00    lea    rsi,[rip+0xe6f]        # 206b <_IO_stdin_used+0x6b>
...
```

Since our ADDR is within a function, RET, OFFSET, or EXITS also needs to be set.
Identify the RET address, which is just after the processing completes:
```
$ objdump -M intel -d targets/vuln_prog_slowinit
...
0000000000001180 <main>:
...
    11d3:       e8 78 01 00 00          call   1350 <process_image>
    -->>11d8:       48 8b 44 24 18          mov    rax,QWORD PTR [rsp+0x18]
    11dd:       64 48 2b 04 25 28 00    sub    rax,QWORD PTR fs:0x28
...
```

Those addresses will be used to control persistent mode:

```
AFL_QEMU_PERSISTENT_GPR=1 \
AFL_QEMU_PERSISTENT_CNT=10000 \
AFL_ENTRYPOINT=$(shell printf "%#x\n" $$(( 0x4000000000 + 0x11f1 ))) \
AFL_QEMU_PERSISTENT_ADDR=$(shell printf "%#x\n" $$(( 0x4000000000 + 0x11f1 ))) \
AFL_QEMU_PERSISTENT_RET=$(shell printf "%#x\n"  $$(( 0x4000000000 + 0x11d8 ))) \
afl-fuzz ...
```

Note, `AFL_QEMU_PERSISTENT_CNT` controls the number of iterations per fork and
`AFL_QEMU_PERSISTENT_GPR` is required to store and recover the registers at the
start of each loop iteration.

We will use the following address for AFL_QEMU_PERSISTENT_ADDR:
```
$ echo $(printf "%#x\n" $((0x4000000000 + 0x11a4)))
0x40000011a4
```

## In-memory fuzzing hook

Note, afl-qemu-trace _must not_ be a static build if this is to be used as the
hook is dynamically linked into the _host_ not the _guest_.

This mode is similar setup to persistent mode above, but we need to compile
a hook which will be linked with QEMU host to perform memcpy of a shared
memory buffer from afl-fuzz to our guest memory. An
[example](src/vuln_prog_persistent_hook) of such a hook is provided which copies
the buffer into the address pointed to by register RDI.

With the hook compiled as a .so, the following `afl-fuzz` environment variables
are _added_, and the target args must use a dummy file (e.g. 4KiB of NIL).

```
AFL_QEMU_PERSISTENT_HOOK=$(TARGET_PROG_PERSIST_HOOK) \
afl-fuzz \
    ...
    --
        <target> tmp/dummy
```

## Issues

### In-memory fuzzing causes segfault in QEMU

I ran into this problem when starting with in-memory fuzzing. The issue
appears to be that I was running with `@@` in my target args which prevents
afl-fuzz entering into the shared memory contract, and so when qemuafl attempts
to dereference the pointer to shared_buf_len it segfaults.

So make sure `@@` is _not_ in the target args!

## More

Full documentation [here].(https://github.com/AFLplusplus/AFLplusplus/blob/fe6d3990ced0b452ac070bdc194dc76162cf9537/qemu_mode/README.persistent.md)