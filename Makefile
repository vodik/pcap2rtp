CFLAGS := -std=c11 \
	-Wall -Wextra -pedantic \
	-Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes \
	-D_GNU_SOURCE \
	$(CFLAGS)

LDLIBS = -lpcap

all: pcap2rtp
pcap2rtp: pcap2rtp.o pcap_parser.o rtp.o pager.o util.o

clean:
	$(RM) pcap2rtp *.o

.PHONY: clean
