
.PHONY: fuzz_01_afl_asan fuzz_02_afl_harden libafl-qemu-run libafl

WORKSPACE = /workspaces/helloworld

AFL_HOME = $(WORKSPACE)/extern/AFLplusplus
AFL_FUZZ = $(AFL_HOME)/afl-fuzz
AFL_CC = $(AFL_HOME)/afl-cc

DVCP_SRCDIR = $(WORKSPACE)/extern/dvcp
DVCP_INPUT = $(WORKSPACE)/dvcp_input
TARGET_01_ASAN = $(WORKSPACE)/targets/01_asan
TARGET_02_HARDEN = $(WORKSPACE)/targets/02_harden
TARGET_03_ASAN_LIB = $(WORKSPACE)/targets/03_imgReadlib.o
TARGET_03_ASAN_BIN = $(WORKSPACE)/targets/03_asan
TARGET_04_ASAN_LIB = $(WORKSPACE)/targets/libimgReadlib.o
TARGET_04_ASAN_BIN = $(WORKSPACE)/targets/04_asan

# AFL++ source-code program with ASAN
fuzz_01_afl_asan: $(TARGET_01_ASAN)
	$(AFL_FUZZ) \
		-i $(DVCP_INPUT) \
		-o output/$@ \
		-- \
			$< @@
$(TARGET_01_ASAN): $(AFL_CC)
	cd $(DVCP_SRCDIR)/linux && \
	$(AFL_CC) -fsanitize=address -fno-omit-frame-pointer -fsanitize=undefined imgRead.c -o $@

# AFL++ source-code program with hardening
fuzz_02_afl_harden: $(TARGET_02_HARDEN)
	$(AFL_FUZZ) \
		-i $(DVCP_INPUT) \
		-o output/$@ \
		-- \
			$< @@
$(TARGET_02_HARDEN): $(AFL_CC)
	cd $(DVCP_SRCDIR)/linux && \
	AFL_HARDEN=1 $(AFL_CC) -fno-omit-frame-pointer imgRead.c -o $@

# AFL++ source-code library (static)
fuzz_03_afl_asan: $(TARGET_03_ASAN_BIN)
	AFL_PRELOAD=$(TARGET_03_ASAN_LIB) $(AFL_FUZZ) \
		-i $(DVCP_INPUT) \
		-o output/$@ \
		-- \
			$< @@
$(TARGET_03_ASAN_BIN): $(AFL_CC)
	cd $(DVCP_SRCDIR)/linux/Damn_Vulnerable_C_lib && \
	$(AFL_CC) -fsanitize=address -c -fno-omit-frame-pointer imgReadlib.c -o $(TARGET_03_ASAN_LIB) && \
	$(AFL_CC) -fsanitize=address -fno-omit-frame-pointer $(TARGET_03_ASAN_LIB) imgRead.c -o $@ 

# AFL++ source-code library (dynamic)
fuzz_04_afl_asan: $(TARGET_04_ASAN_BIN)
	AFL_PRELOAD=$(TARGET_04_ASAN_LIB) $(AFL_FUZZ) \
		-i $(DVCP_INPUT) \
		-o output/$@ \
		-- \
			$< @@
$(TARGET_04_ASAN_BIN): $(AFL_CC)
	cd $(DVCP_SRCDIR)/linux/Damn_Vulnerable_C_lib && \
	$(AFL_CC) -fsanitize=address -shared -fno-omit-frame-pointer imgReadlib.c -o $(TARGET_04_ASAN_LIB) && \
	$(AFL_CC) -fsanitize=address -fno-omit-frame-pointer $(TARGET_04_ASAN_LIB) imgRead.c -o $@ 








$(AFL_CC) $(AFL_FUZZ):
	cd extern/AFLplusplus && \
	make distrib

libafl-qemu-run:
	cd libafl_qemu && \
	cargo make run

libafl:
	cd extern/LibAFL && \
	cargo build --release
