
.PHONY: clean fuzz_01_afl_asan_file fuzz_02_afl_asan_stdin fuzz_03_afl_harden fuzz_04_afl_asan_persist fuzz_05_afl_asan_shmem fuzz_06_afl_harden fuzz_07_afl_asan     libafl-qemu-run libafl

WORKSPACE = /workspaces/helloworld

AFL_HOME    = $(WORKSPACE)/extern/AFLplusplus
AFL_FUZZ    = $(AFL_HOME)/afl-fuzz
HONGGFUZZ   = $(WORKSPACE)/extern/honggfuzz/honggfuzz
HFUZZ_CC    = $(WORKSPACE)/extern/honggfuzz/hfuzz_cc/hfuzz-pcguard-clang
LIBAFL_FUZZ = $(WORKSPACE)/extern/LibAFL/fuzzers/forkserver/libafl-fuzz/target/release/libafl-fuzz
AFL_CC      = $(AFL_HOME)/afl-cc
CLANG       = /usr/bin/clang

CORPUS = $(WORKSPACE)/fuzz_input

SRC_VULN_PROG_DIR         = $(WORKSPACE)/src/vuln_prog
TARGET_PROG_ASAN          = $(WORKSPACE)/targets/vuln_prog_asan
TARGET_PROG_HONGGFUZZ     = $(WORKSPACE)/targets/vuln_prog_honggfuzz
TARGET_PROG_HARDEN        = $(WORKSPACE)/targets/vuln_prog_harden
SRC_VULN_PROG_PERSIST_DIR = $(WORKSPACE)/src/vuln_prog_persist
TARGET_PROG_PERSIST_ASAN  = $(WORKSPACE)/targets/vuln_prog_persist_asan
SRC_VULN_PROG_SHMEM_DIR   = $(WORKSPACE)/src/vuln_prog_shmem
TARGET_PROG_SHMEM_ASAN    = $(WORKSPACE)/targets/vuln_prog_shmem_asan

SRC_VULN_LIB_DIR          = $(WORKSPACE)/src/vuln_lib
SRC_VULN_LIB_HARNESS      = $(WORKSPACE)/src/vuln_lib_harness/harness.c
SRC_VULN_LIB_HARNESS_LF   = $(WORKSPACE)/src/vuln_lib_harness/libfuzzer_target.c
TARGET_LIB_DIR            = $(WORKSPACE)/targets/lib
TARGET_LIB_STATIC_BIN     = $(WORKSPACE)/targets/vuln_lib_static_bin
TARGET_LIB_STATIC_LF_BIN  = $(WORKSPACE)/targets/vuln_lib_libfuzzer_static
TARGET_LIB_DYNAMIC_BIN    = $(WORKSPACE)/targets/vuln_lib_dynamic_bin

##
## Source-code programs
##

# AFL++ source-code program w/ ASAN + CMPLOG - using file inputs
fuzz_01_afl_asan_file: $(TARGET_PROG_ASAN)
	AFL_PIZZA_MODE=1 \
	$(AFL_FUZZ) \
		-i $(CORPUS) \
		-o output/$@ \
		-c $<.cmplog \
		-- \
			$< @@
$(TARGET_PROG_ASAN): $(AFL_CC)
	cd $(SRC_VULN_PROG_DIR) && \
	autoreconf -i && \
	./configure CC=$(AFL_CC) AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" && \
	make clean && \
	make AFL_USE_ASAN=1 && \
	mv imgRead $@ && \
	./configure CC=$(AFL_CC) AFL_LLVM_CMPLOG=1 AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" && \
	make clean && \
	make AFL_LLVM_CMPLOG=1 AFL_USE_ASAN=1 && \
	mv imgRead $@.cmplog

# libafl-fuzz source-code program w/ ASAN + CMPLOG (incomplete port of afl++ to Rust/LibAFL)
fuzz01_libaflfuzz_asan_file: $(TARGET_PROG_ASAN)
	AFL_CORES=0-28 \
	$(LIBAFL_FUZZ) \
		-i $(CORPUS) \
		-o output/$@ \
		-c $<.cmplog \
			$<

# Honggfuzz source-code program w/ ASAN - using file inputs
fuzz_01_honggfuzz_file: $(TARGET_PROG_HONGGFUZZ) $(HONGGFUZZ)
	cd tmp && $(HONGGFUZZ) \
		-i $(CORPUS) \
		-z \
		-- \
			$< ___FILE___
$(TARGET_PROG_HONGGFUZZ): $(HFUZZ_CC)
	cd $(SRC_VULN_PROG_DIR) && \
	autoreconf -i && \
	./configure CC=$(HFUZZ_CC) HFUZZ_CC_ASAN=1 HFUZZ_CC_UBSAN=1 CFLAGS="-fno-omit-frame-pointer" && \
	make clean && \
	make HFUZZ_CC_ASAN=1 HFUZZ_CC_UBSAN=1 && \
	mv imgRead $@
# Honggfuzz source-code program w/ ASAN - using stdin
fuzz_01_honggfuzz_stdin: $(TARGET_PROG_HONGGFUZZ) $(HONGGFUZZ)
	cd tmp && $(HONGGFUZZ) \
		-i $(CORPUS) \
		-z \
		-s \
		-- \
			$<

# AFL++ source-code program w/ ASAN + CMPLOG - using stdin
fuzz_02_afl_asan_stdin: $(TARGET_PROG_ASAN)
	$(AFL_FUZZ) \
		-i $(CORPUS) \
		-o output/$@ \
		-c $<.cmplog \
		-- \
			$<

# AFL++ source-code program with hardening/CMPLOG - using file inputs
fuzz_03_afl_harden: $(TARGET_PROG_HARDEN)
	$(AFL_FUZZ) \
		-i $(CORPUS) \
		-o output/$@ -P exploit \
		-c $<.cmplog \
		-- \
			$< @@
$(TARGET_PROG_HARDEN): $(AFL_CC)
	cd $(SRC_VULN_PROG_DIR) && \
	autoreconf -i && \
	./configure CC=$(AFL_CC) AFL_HARDEN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" && \
	make clean && \
	make AFL_HARDEN=1 && \
	mv imgRead $@ && \
	./configure CC=$(AFL_CC) AFL_LLVM_CMPLOG=1 AFL_HARDEN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" && \
	make clean && \
	make AFL_LLVM_CMPLOG=1 AFL_HARDEN=1 && \
	mv imgRead $@.cmplog

# Deferred fork-server + persistent mode to defeat slow initialisation.
# Must use file input; STDIN won't work.
fuzz_04_afl_asan_persist: $(TARGET_PROG_PERSIST_ASAN)
	$(AFL_FUZZ) \
		-i $(CORPUS) \
		-o output/$@ \
		-c $<.cmplog \
		-- \
			$< @@
$(TARGET_PROG_PERSIST_ASAN): $(AFL_CC)
	cd $(SRC_VULN_PROG_PERSIST_DIR) && \
	autoreconf -i && \
	./configure CC=$(AFL_CC) AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" && \
	make clean && \
	make AFL_USE_ASAN=1 && \
	mv imgRead $@ && \
	./configure CC=$(AFL_CC) AFL_LLVM_CMPLOG=1 AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" && \
	make clean && \
	make AFL_LLVM_CMPLOG=1 AFL_USE_ASAN=1 && \
	mv imgRead $@.cmplog

# Add shared memory fuzzing.
# File/STDIN input options are ignored.
fuzz_05_afl_asan_shmem: $(TARGET_PROG_SHMEM_ASAN)
	$(AFL_FUZZ) \
		-i $(CORPUS) \
		-o output/$@ \
		-c $<.cmplog \
		-- \
			$<
$(TARGET_PROG_SHMEM_ASAN): $(AFL_CC)
	cd $(SRC_VULN_PROG_SHMEM_DIR) && \
	autoreconf -i && \
	./configure CC=$(AFL_CC) AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" && \
	make clean && \
	make AFL_USE_ASAN=1 && \
	mv imgRead $@ && \
	./configure CC=$(AFL_CC) AFL_LLVM_CMPLOG=1 AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" && \
	make clean && \
	make AFL_LLVM_CMPLOG=1 AFL_USE_ASAN=1 && \
	mv imgRead $@.cmplog

##
## Source-code libraries
##

# AFL++ source-code library (static) w/ CMPLOG - ASAN not supported on static builds
fuzz_06_afl_harden: $(TARGET_LIB_STATIC_BIN)
	$(AFL_FUZZ) \
		-i $(CORPUS) \
		-o output/$@ \
		-c $<.cmplog \
		-- \
			$<
$(TARGET_LIB_STATIC_BIN): $(SRC_VULN_LIB_HARNESS) $(AFL_CC)
	cd $(SRC_VULN_LIB_DIR) && \
	autoreconf -i && \
	./configure CC=$(AFL_CC) AFL_HARDEN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" --prefix=$(shell dirname $<)/libs && \
	make clean && \
	make AFL_HARDEN=1 && \
	make install

	cd $(shell dirname $<) && \
	make CC=$(AFL_CC) AFL_HARDEN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" clean vuln_lib_static_harness && \
	mv vuln_lib_static_harness $@

	cd $(SRC_VULN_LIB_DIR) && \
	./configure CC=$(AFL_CC) AFL_LLVM_CMPLOG=1 AFL_HARDEN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" --prefix=$(shell dirname $<)/libs && \
	make clean && \
	make AFL_LLVM_CMPLOG=1 AFL_HARDEN=1 && \
	make install

	cd $(shell dirname $<) && \
	make CC=$(AFL_CC) AFL_HARDEN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" clean vuln_lib_static_harness && \
	mv vuln_lib_static_harness $@.cmplog

# LibFuzzer source-code library (dynamic) w/ ASAN
# For cmdline options see: https://llvm.org/docs/LibFuzzer.html
fuzz_07_libfuzzer: $(TARGET_LIB_STATIC_LF_BIN)
	LD_LIBRARY_PATH=$(TARGET_LIB_DIR) $(TARGET_LIB_STATIC_LF_BIN) $(CORPUS)
$(TARGET_LIB_STATIC_LF_BIN): $(SRC_VULN_LIB_HARNESS_LF) $(CLANG) $(TARGET_LIB_DIR)
	cd $(SRC_VULN_LIB_DIR) && \
	autoreconf -i && \
	./configure CC=$(CLANG) CFLAGS="-g -O1 -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer" --prefix=$(shell dirname $<)/libs && \
	make clean && \
	make && \
	make install

	cd $(shell dirname $<) && \
	make CC=$(CLANG) CFLAGS="-g -O1 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer" clean vuln_lib_libfuzzer_dynamic_harness && \
	mv vuln_lib_libfuzzer_dynamic_harness $@ && \
	cp libs/lib/libimgread.so.0 $(TARGET_LIB_DIR)

# AFL++ source-code library (dynamic) - w/ ASAN + CMPLOG
fuzz_07_afl_asan: $(TARGET_LIB_DYNAMIC_BIN)
	AFL_TARGET_ENV=LD_LIBRARY_PATH=$(TARGET_LIB_DIR) \
	$(AFL_FUZZ) \
		-i $(CORPUS) \
		-o output/$@ \
		-c $<.cmplog \
		-- \
			$<
$(TARGET_LIB_DYNAMIC_BIN): $(SRC_VULN_LIB_HARNESS) $(AFL_CC) $(TARGET_LIB_DIR)
	cd $(SRC_VULN_LIB_DIR) && \
	autoreconf -i && \
	./configure CC=$(AFL_CC) AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" --prefix=$(shell dirname $<)/libs && \
	make clean && \
	make AFL_USE_ASAN=1 && \
	make install

	cd $(shell dirname $<) && \
	make CC=$(AFL_CC) AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" vuln_lib_dynamic_harness && \
	mv vuln_lib_dynamic_harness $@ && \
	cp libs/lib/libimgread.so.0 $(TARGET_LIB_DIR)
	
	cd $(SRC_VULN_LIB_DIR) && \
	sed -r -i 's/(libimgread)/\1_cmplog/g' configure.ac && \
	sed -r -i 's/(libimgread)/\1_cmplog/g' Makefile.am && \
	autoreconf -i && \
	./configure CC=$(AFL_CC) AFL_LLVM_CMPLOG=1 AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" --prefix=$(shell dirname $<)/libs && \
	make clean && \
	make AFL_LLVM_CMPLOG=1 AFL_USE_ASAN=1 && \
	make install && \
	git checkout configure.ac Makefile.am
	
	cd $(shell dirname $<) && \
	make CC=$(AFL_CC) AFL_LLVM_CMPLOG=1 AFL_USE_ASAN=1 CFLAGS="-fno-omit-frame-pointer -fsanitize=undefined" vuln_lib_dynamic_harness.cmplog && \
	mv vuln_lib_dynamic_harness.cmplog $@.cmplog && \
	cp libs/lib/libimgread_cmplog.so.0 $(TARGET_LIB_DIR)

clean:
	rm -rf targets/* output/* core crash-* .cur_input_*

$(TARGET_LIB_DIR):
	mkdir -p $@

$(AFL_CC) $(AFL_FUZZ):
	cd extern/AFLplusplus && \
	make distrib

$(LIBAFL_FUZZ):
	cd $(LIBAFL_FUZZ)/../../.. && \
	cargo build --release

$(HFUZZ_CC) $(HONGGFUZZ):
	cd $(HONGGFUZZ)/.. && \
	make

libafl-qemu-run:
	cd libafl_qemu && \
	cargo make run

libafl:
	cd extern/LibAFL && \
	cargo build --release
