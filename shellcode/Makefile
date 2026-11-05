NASM      := nasm
NASM_FLAGS := -f bin
PYTHON    := python3

all: combined/shellcode.bin combined/sqpoll_min.bin

combined/shellcode.bin: combined/shellcode.asm
	$(NASM) $(NASM_FLAGS) -o $@ $<
	$(PYTHON) combined/extract.py $@ --no-array

# ROADMAP #1 — SQPOLL zero-syscall variant (< 500 bytes, needs kernel >= 5.11)
combined/sqpoll_min.bin: combined/sqpoll_min.asm
	$(NASM) $(NASM_FLAGS) -o $@ $<
	$(PYTHON) combined/extract.py $@ --no-array

check:
	$(PYTHON) combined/extract.py combined/shellcode.bin --no-array

array:
	$(PYTHON) combined/extract.py combined/shellcode.bin

patch:
	$(PYTHON) patch_config.py combined/shellcode.bin \
		--ip $(TARGET_IP) --port $(TARGET_PORT)

clean:
	rm -f combined/shellcode.bin combined/shellcode.h \
	      combined/sqpoll_min.bin \
	      combined/shellcode_patched.bin missions/*.bin

.PHONY: all check array patch clean
