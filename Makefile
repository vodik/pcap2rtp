libpcap_CFLAGS = $(shell pcap-config --cflags)
libpcap_LDLIBS = $(shell pcap-config --libs)

libpulse_CFLAGS = $(shell pkg-config --cflags libpulse-simple)
libpulse_LDLIBS = $(shell pkg-config --libs libpulse-simple)

CFLAGS := -std=c11 \
	-Wall -Wextra -pedantic \
	-Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes \
	-D_GNU_SOURCE \
	${libpcap_CFLAGS} \
	${libpulse_CFLAGS} \
	$(CFLAGS)

LDLIBS = ${libpcap_LDLIBS} ${libpulse_LDLIBS}

all: pcap2rtp
pcap2rtp: pcap2rtp.o parser.o rtp.o pager.o util.o

clean:
	$(RM) pcap2rtp pulse *.o

.PHONY: clean
