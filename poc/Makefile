CC     := gcc
CFLAGS := -Wall -Wextra -O0 -g
IFLAGS := -I/usr/include/x86_64-linux-gnu

TARGETS := hello_uring file_exfil_uring sqpoll_uring

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) $(IFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
