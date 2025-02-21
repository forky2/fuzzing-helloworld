WORKSPACE = /workspaces/helloworld

AFL_HOME    = $(WORKSPACE)/extern/AFLplusplus
AFL_FUZZ    = $(AFL_HOME)/afl-fuzz
HONGGFUZZ   = $(WORKSPACE)/extern/honggfuzz/honggfuzz
HFUZZ_CC    = $(WORKSPACE)/extern/honggfuzz/hfuzz_cc/hfuzz-pcguard-clang
LIBAFL_FUZZ = $(WORKSPACE)/extern/LibAFL/fuzzers/forkserver/libafl-fuzz/target/release/libafl-fuzz
AFL_CC      = $(AFL_HOME)/afl-cc
LAFL_QL     = $(WORKSPACE)/libafl_qemu/target/release/qemu_launcher
CLANG       = /usr/bin/clang

CORPUS = $(WORKSPACE)/corpus
OUTPUT = $(WORKSPACE)/output

SRC_VULN_PROG_DIR         = $(WORKSPACE)/src/vuln_prog
SRC_VULN_PROG_HOOK_DIR    = $(WORKSPACE)/src/vuln_prog_persistent_hook
TARGET_PROG               = $(WORKSPACE)/targets/vuln_prog
TARGET_PROG_PERSIST_HOOK  = $(WORKSPACE)/targets/vuln_prog_persistent_hook.so
TARGET_PROG_SLOWINIT      = $(WORKSPACE)/targets/vuln_prog_slowinit
TARGET_PROG_ASAN          = $(WORKSPACE)/targets/vuln_prog_asan
TARGET_PROG_HONGGFUZZ     = $(WORKSPACE)/targets/vuln_prog_honggfuzz
TARGET_PROG_HARDEN        = $(WORKSPACE)/targets/vuln_prog_harden
SRC_VULN_PROG_SLOWINIT    = $(WORKSPACE)/src/vuln_prog_slowinit
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
.PHONY: fuzz_01_afl_asan_file
fuzz_01_afl_asan_file: $(TARGET_PROG_ASAN) $(AFL_FUZZ)
	AFL_PIZZA_MODE=1 \
	$(AFL_FUZZ) \
		-i $(CORPUS) \
		-o $(OUTPUT)/$@ \
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
.PHONY: fuzz_01_libaflfuzz_asan_file
fuzz_01_libaflfuzz_asan_file: $(TARGET_PROG_ASAN) $(LIBAFL_FUZZ)
	cd tmp && \
	AFL_CORES=0-15 \
	$(LIBAFL_FUZZ) \
		-i $(CORPUS) \
		-o $(OUTPUT)/$@ \
		-c $<.cmplog \
			$<

# Honggfuzz source-code program w/ ASAN - using file inputs
.PHONY: fuzz_01_honggfuzz_file
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
.PHONY: fuzz_01_honggfuzz_stdin
fuzz_01_honggfuzz_stdin: $(TARGET_PROG_HONGGFUZZ) $(HONGGFUZZ)
	cd tmp && $(HONGGFUZZ) \
		-i $(CORPUS) \
		-z \
		-s \
		-- \
			$<

# AFL++ source-code program w/ ASAN + CMPLOG - using stdin
.PHONY: fuzz_02_afl_asan_stdin
fuzz_02_afl_asan_stdin: $(TARGET_PROG_ASAN)
	$(AFL_FUZZ) \
		-i $(CORPUS) \
		-o output/$@ \
		-c $<.cmplog \
		-- \
			$<

# AFL++ source-code program with hardening/CMPLOG - using file inputs
.PHONY: fuzz_03_afl_harden
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
.PHONY: fuzz_04_afl_asan_persist
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
.PHONY: fuzz_05_afl_asan_shmem
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
.PHONY: fuzz_06_afl_harden
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
.PHONY: fuzz_07_libfuzzer
fuzz_07_libfuzzer: $(TARGET_LIB_STATIC_LF_BIN)
	cd tmp && \
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
.PHONY: fuzz_07_afl_asan
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

##
## Binary-only simulations
##

# GCC compiled program - AFL++ QEMU mode - using file inputs
.PHONY: fuzz_11_afl_qemu_file
fuzz_11_afl_qemu_file: $(TARGET_PROG_SLOWINIT) $(AFL_FUZZ)
	AFL_QEMU_PERSISTENT_MEM=1 \
	$(AFL_FUZZ) \
		-Q \
		-i $(CORPUS) \
		-o $(OUTPUT)/$@ \
		-c 0 \
		-- \
			$< @@
$(TARGET_PROG_SLOWINIT):
	cd $(SRC_VULN_PROG_SLOWINIT) && \
	autoreconf -i && \
	./configure CFLAGS="-O2" && \
	make clean && \
	make && \
	mv imgRead $@

# GCC compiled program - AFL++ QEMU mode - stdin
.PHONY: fuzz_11_afl_qemu_stdin
fuzz_11_afl_qemu_stdin: $(TARGET_PROG_SLOWINIT) $(AFL_FUZZ)
	AFL_QEMU_PERSISTENT_MEM=1 \
	$(AFL_FUZZ) \
		-Q \
		-i $(CORPUS) \
		-o $(OUTPUT)/$@ \
		-c 0 \
		-- \
			$<

# GCC compiled program - AFL++ QEMU mode - deferred; see docs/afl_qemu_deferred.md
.PHONY: fuzz_11_afl_qemu_defer
fuzz_11_afl_qemu_defer: $(TARGET_PROG_SLOWINIT) $(AFL_FUZZ)
	AFL_QEMU_PERSISTENT_MEM=1 \
	AFL_ENTRYPOINT=$(shell printf "%#x\n" $$((0x4000000000 + 0x11fd))) \
	$(AFL_FUZZ) \
		-Q \
		-i $(CORPUS) \
		-o $(OUTPUT)/$@ \
		-c 0 \
		-- \
			$< @@

# GCC compiled program - AFL++ QEMU mode - persistent; see docs/afl_qemu_persistent.md
.PHONY: fuzz_11_afl_qemu_persist
fuzz_11_afl_qemu_persist: $(TARGET_PROG_SLOWINIT) $(AFL_FUZZ)
	AFL_QEMU_PERSISTENT_MEM=1 \
	AFL_QEMU_PERSISTENT_EXITS=1 \
	AFL_QEMU_PERSISTENT_GPR=1 \
	AFL_QEMU_PERSISTENT_CNT=10000 \
	AFL_ENTRYPOINT=$(shell printf "%#x\n" $$((0x4000000000 + 0x11fd))) \
	AFL_QEMU_PERSISTENT_ADDR=$(shell printf "%#x\n" $$(( 0x4000000000 + 0x11fd ))) \
	AFL_QEMU_PERSISTENT_RET=$(shell printf "%#x\n"  $$(( 0x4000000000 + 0x11e4 ))) \
	$(AFL_FUZZ) \
		-Q \
		-i $(CORPUS) \
		-o $(OUTPUT)/$@ \
		-c 0 \
		-- \
			$< @@

# GCC compiled program - AFL++ QEMU mode - in-memory; see docs/afl_qemu_persistent.md
.PHONY: fuzz_11_afl_qemu_persist_hook
fuzz_11_afl_qemu_persist_hook: $(TARGET_PROG_SLOWINIT) $(AFL_FUZZ) $(TARGET_PROG_PERSIST_HOOK)
	dd if=/dev/zero of=tmp/dummy bs=1k count=4
	AFL_QEMU_PERSISTENT_MEM=1 \
	AFL_QEMU_PERSISTENT_EXITS=1 \
	AFL_QEMU_PERSISTENT_GPR=1 \
	AFL_QEMU_PERSISTENT_CNT=10000 \
	AFL_ENTRYPOINT=$(shell printf "%#x\n" $$(( 0x4000000000 + 0x11df ))) \
	AFL_QEMU_PERSISTENT_ADDR=$(shell printf "%#x\n" $$(( 0x4000000000 + 0x11df ))) \
	AFL_QEMU_PERSISTENT_RET=$(shell printf "%#x\n"  $$(( 0x4000000000 + 0x11e4 ))) \
	AFL_QEMU_PERSISTENT_HOOK=$(TARGET_PROG_PERSIST_HOOK) \
	$(AFL_FUZZ) \
		-Q \
		-i $(CORPUS) \
		-o $(OUTPUT)/$@ \
		-c 0 \
		-- \
			$< tmp/dummy
$(TARGET_PROG_PERSIST_HOOK): $(SRC_VULN_PROG_HOOK_DIR)
	cd $(SRC_VULN_PROG_HOOK_DIR) && \
	make all && \
	cp read_into_rdi.so $@

# GCC compiled program - LibAFL's qemu_launcher example
# 5.256M exec/s
.PHONY: fuzz_11_libafl_qemu_launcher
fuzz_11_libafl_qemu_launcher: $(TARGET_PROG_SLOWINIT) $(LAFL_QL)
	RUST_LOG=info \
	$(LAFL_QL) \
	--input $(CORPUS) \
	--output $(OUTPUT)/$@ \
	--log tmp/qemu_launcher.log \
	--cores 0 \
	-v \
	--include 0x0-0xffffffffffffffff \
	--entrypoint $(shell printf "%#x\n" $$(( 0x0000555555556000 + 0x11dc ))) \
	--exitpoint $(shell printf "%#x\n" $$(( 0x0000555555556000 + 0x11e1 ))) \
	-- \
		$< tmp/dummy

.PHONY: clean
clean:
	rm -rf tmp/* tmp/.cur_input_* targets/* output/* core *.core crash-* .cur_input_*

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

$(LAFL_QL):
	cd libafl_qemu && \
	PROFILE=release ARCH=x86_64 just build

.PHONY: libafl-qemu-run
libafl-qemu-run:
	cd libafl_qemu && \
	cargo make run

.PHONY: clean
libafl:
	cd extern/LibAFL && \
	cargo build --release
