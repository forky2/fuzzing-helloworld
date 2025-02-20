# Fuzzing with LibAFL QEMU components

The existing qemu_launcher is just an example of capability and is written to
start the target (a C harness with a main function) in QEMU, find the symbol for
LLVMFuzzerTestOneInput (via symbols).

It requests QEMU sets and runs until a breakpoint on that address. That point
becomes the state for forking and for persistent mode fuzzing. It also reveals
the return address of the function (since that's now on the stack in x86_64).
That address can become a breakpoint for the test case completion.

I modify qemu_launcher to just use a start and end address in command line
parameters.

The other change is that the shared memory buffer isn't going into cdecl calling
convention registers 0 and 1; instead I want to actually perform a memcpy from
the shared memory buffer to the buffer in the target (which a register is
pointing to).
