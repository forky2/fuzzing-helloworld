
.PHONY: aflplusplus libafl libafl-qemu-run

libafl-qemu-run:
	cd libafl_qemu && \
	cargo make run

aflplusplus:
	cd extern/AFLplusplus && \
	make distrib && \
	sudo make install

libafl:
	cd extern/LibAFL && \
	cargo build --release
