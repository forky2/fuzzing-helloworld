
.PHONY: fuzz_01_afl_asan fuzz_02_afl_harden libafl-qemu-run libafl

WORKSPACE = /workspaces/helloworld

AFL_HOME = $(WORKSPACE)/extern/AFLplusplus
AFL_FUZZ = $(AFL_HOME)/afl-fuzz
AFL_CC = $(AFL_HOME)/afl-cc

DVCP_SRCDIR = $(WORKSPACE)/extern/dvcp
DVCP_INPUT = $(WORKSPACE)/dvcp_input
TARGET_01_ASAN = $(WORKSPACE)/targets/01_asan
TARGET_02_HARDEN = $(WORKSPACE)/targets/02_harden

# AFL++ source-code program with ASAN
fuzz_01_afl_asan: $(TARGET_01_ASAN)
	$(AFL_FUZZ) \
		-i $(DVCP_INPUT) \
		-o output/$@ \
		-- \
			$< @@
$(TARGET_01_ASAN): $(AFL_CC)
	cd $(DVCP_SRCDIR) && \
	$(AFL_CC) -fsanitize=address -fno-omit-frame-pointer -fsanitize=undefined imgRead.c -o $@

# AFL++ source-code program with hardening
fuzz_02_afl_harden: $(TARGET_02_HARDEN)
	$(AFL_FUZZ) \
		-i $(DVCP_INPUT) \
		-o output/$@ \
		-- \
			$< @@
$(TARGET_02_HARDEN): $(AFL_CC)
	cd $(DVCP_SRCDIR) && \
	AFL_HARDEN=1 $(AFL_CC) -fno-omit-frame-pointer imgRead.c -o $@

# AFL++ source-code library with ASAN







$(AFL_CC) $(AFL_FUZZ):
	cd extern/AFLplusplus && \
	make distrib

libafl-qemu-run:
	cd libafl_qemu && \
	cargo make run

libafl:
	cd extern/LibAFL && \
	cargo build --release
