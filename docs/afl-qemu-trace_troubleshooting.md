# Troubleshooting AFL++ QEMU mode

If you need to debug, modify code in qemu_mode/qemuafl and recompile by running
in qemu_mode directory:
```
NO_CHECKOUT=1 ./build_qemu_support.sh
cp qemuafl/build/qemu-x86_64 ../afl-qemu-trace
```
