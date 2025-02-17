.PHONY: clean

vuln_lib_static_harness: harness.c libs/lib/libimgread.a libs/include/imgread.h
	$(CC) $(CFLAGS) -static -Ilibs/include -Llibs/lib  -o $@ $< -limgread

vuln_lib_dynamic_harness: harness.c libs/lib/libimgread.a libs/include/imgread.h
	$(CC) $(CFLAGS) -Ilibs/include -Llibs/lib -o $@ $< -limgread

vuln_lib_dynamic_harness.cmplog: harness.c libs/lib/libimgread.a libs/include/imgread.h
	$(CC) $(CFLAGS) -Ilibs/include -Llibs/lib -o $@ $< -limgread_cmplog

vuln_lib_libfuzzer_dynamic_harness: libfuzzer_target.c libs/lib/libimgread.a libs/include/imgread.h
	$(CC) $(CFLAGS) -Ilibs/include -Llibs/lib -o $@ $< -limgread

make clean:
	rm -f vuln_lib_static_harness vuln_lib_dynamic_harness vuln_lib_dynamic_harness.cmplog vuln_lib_libfuzzer_dynamic_harness