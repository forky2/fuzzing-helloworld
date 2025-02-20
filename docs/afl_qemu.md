# AFL++ QEMU mode

QEMU mode is simply `-Q` mode in `afl-fuzz`. The command line arguments are
similar to fuzzing an instrumented binary; the hard work might be in targetting
the interesting function(s) in a binary that does a lot of stuff that isn't.

There are particular optimisations:

* [Deferred forkserver](./afl_qemu_deferred.md)
* [Persistent mode and shared memory](./afl_qemu_persistent.md)

## CMPLOG

CMPLOG can be enabled by simply adding the `-c 0` parameter to `afl-fuzz`. No
special binary is required.

## Snapshot mode

Documentation suggests that this mode is obsolete. It used to say:

    `AFL_QEMU_SNAPSHOT=address` is just a "syntactical sugar" environment variable
    that is equivalent to the following set of variables:
    ```
    AFL_QEMU_PERSISTENT_ADDR=address
    AFL_QEMU_PERSISTENT_GPR=1
    AFL_QEMU_PERSISTENT_MEM=1
    AFL_QEMU_PERSISTENT_EXITS=1
    ```

I use the `AFL_QEMU_PERSISTENT_MEM` env by default anyway, and the rest I add
as part of [persistent mode](./afl_qemu_persistent.md).
