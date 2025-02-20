# AFL++ QEMU deferred mode

## Deferred mode

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
a basic block):
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

We will use the following address for AFL_ENTRYPOINT:
```
$ echo $(printf "%#x\n" $((0x4000000000 + 11f1)))
0x40000011f1
```

## More

Full documentation [here].(https://github.com/AFLplusplus/AFLplusplus/blob/fe6d3990ced0b452ac070bdc194dc76162cf9537/qemu_mode/README.deferred_initialization_example.md)