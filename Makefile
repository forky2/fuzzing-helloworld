
.PHONY: clean fuzz_01_afl_asan fuzz_02_afl_harden fuzz_03_afl_asan fuzz_04_afl_harden fuzz_05_afl_asan       libafl-qemu-run libafl

WORKSPACE = /workspaces/helloworld

AFL_HOME = $(WORKSPACE)/extern/AFLplusplus
AFL_FUZZ = $(AFL_HOME)/afl-fuzz
AFL_CC = $(AFL_HOME)/afl-cc

FUZZ_INPUT = $(WORKSPACE)/fuzz_input

TARGET_LIB_DIR         = $(WORKSPACE)/targets/lib
SRC_VULN_PROG_DIR      = $(WORKSPACE)/src/vuln_prog
TARGET_PROG_ASAN       = $(WORKSPACE)/targets/vuln_prog_asan
TARGET_PROG_HARDEN     = $(WORKSPACE)/targets/vuln_prog_harden

SRC_VULN_LIB_DIR       = $(WORKSPACE)/src/vuln_lib
SRC_VULN_LIB_HARNESS   = $(WORKSPACE)/src/vuln_lib_harness/harness.c
TARGET_LIB_STATIC_BIN  = $(WORKSPACE)/targets/vuln_lib_static_bin
TARGET_LIB_DYNAMIC_BIN = $(WORKSPACE)/targets/vuln_lib_dynamic_bin

TARGET_03_ASAN_LIB = $(WORKSPACE)/targets/03_imgReadlib.o
TARGET_03_ASAN_BIN = $(WORKSPACE)/targets/03_asan
TARGET_04_ASAN_LIB = $(WORKSPACE)/targets/libimgReadlib.o
TARGET_04_ASAN_BIN = $(WORKSPACE)/targets/04_asan

# AFL++ source-code program with ASAN - using file inputs
fuzz_01_afl_asan: $(TARGET_PROG_ASAN)
	$(AFL_FUZZ) \
		-i $(FUZZ_INPUT) \
		-o output/$@ \
		-c $<.cmplog \
		-- \
			$< @@
$(TARGET_PROG_ASAN): $(AFL_CC)
	cd $(SRC_VULN_PROG_DIR) && \
	autoreconf -i && \
	./configure && \
	make clean && \
	make CC=$(AFL_CC) AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer" && \
	mv imgRead $@ && \
	AFL_LLVM_CMPLOG=1 ./configure && \
	make AFL_LLVM_CMPLOG=1 clean && \
	make AFL_LLVM_CMPLOG=1 CC=$(AFL_CC) AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer" && \
	mv imgRead $@.cmplog

# AFL++ source-code program with hardening - using file inputs
fuzz_02_afl_harden: $(TARGET_PROG_HARDEN)
	$(AFL_FUZZ) \
		-i $(FUZZ_INPUT) \
		-o output/$@ -P exploit \
		-- \
			$< @@
$(TARGET_PROG_HARDEN): $(AFL_CC)
	cd $(SRC_VULN_PROG_DIR) && \
	autoreconf -i && \
	./configure && \
	make clean && \
	make CC=$(AFL_CC) AFL_HARDEN=1 CFLAGS="-fno-omit-frame-pointer" && \
	mv imgRead $@

# AFL++ source-code program with ASAN - this time using STDIN
fuzz_03_afl_asan: $(TARGET_PROG_ASAN)
	$(AFL_FUZZ) \
		-i $(FUZZ_INPUT) \
		-o output/$@ \
		-- \
			$<

# AFL++ source-code library (static) - ASAN not supported on static builds
fuzz_04_afl_harden: $(TARGET_LIB_STATIC_BIN)
	$(AFL_FUZZ) \
		-i $(FUZZ_INPUT) \
		-o output/$@ \
		-- \
			$<
$(TARGET_LIB_STATIC_BIN): $(SRC_VULN_LIB_HARNESS) $(AFL_CC)
	cd $(SRC_VULN_LIB_DIR) && \
	autoreconf -i && \
	./configure --prefix=$(shell dirname $<)/libs && \
	make clean && \
	make CC=$(AFL_CC) AFL_HARDEN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" && \
	make install
	cd $(shell dirname $<) && \
	make CC=$(AFL_CC) AFL_HARDEN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" vuln_lib_static_harness && \
	mv vuln_lib_static_harness $@

# AFL++ source-code library (dynamic) - ASAN mode
fuzz_05_afl_asan: $(TARGET_LIB_DYNAMIC_BIN)
	AFL_TARGET_ENV=LD_LIBRARY_PATH=$(TARGET_LIB_DIR) \
	$(AFL_FUZZ) \
		-i $(FUZZ_INPUT) \
		-o output/$@ \
		-- \
			$<
$(TARGET_LIB_DYNAMIC_BIN): $(SRC_VULN_LIB_HARNESS) $(AFL_CC) $(TARGET_LIB_DIR)
	cd $(SRC_VULN_LIB_DIR) && \
	autoreconf -i && \
	./configure --prefix=$(shell dirname $<)/libs && \
	make clean && \
	make CC=$(AFL_CC) AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" && \
	make install
	cd $(shell dirname $<) && \
	make CC=$(AFL_CC) AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" vuln_lib_dynamic_harness && \
	mv vuln_lib_dynamic_harness $@ && \
	cp libs/lib/libimgread.so.0 $(TARGET_LIB_DIR)

clean:
	rm -rf targets/*

$(TARGET_LIB_DIR):
	mkdir -p $@

$(AFL_CC) $(AFL_FUZZ):
	cd extern/AFLplusplus && \
	make distrib

libafl-qemu-run:
	cd libafl_qemu && \
	cargo make run

libafl:
	cd extern/LibAFL && \
	cargo build --release
