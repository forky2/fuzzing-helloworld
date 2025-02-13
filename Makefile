
.PHONY: aflplusplus libafl

aflplusplus:
	cd extern/AFLplusplus && \
	make distrib && \
	sudo make install

libafl:
	cd extern/LibAFL && \
	cargo build --release
