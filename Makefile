CFLAGS := -std=c11 \
	-Wall -Wextra -pedantic \
	-Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes \
	-D_GNU_SOURCE \
	$(CFLAGS)

libpulse_CFLAGS = $(shell pkg-config --cflags libpulse-simple)
libpulse_LDLIBS = $(shell pkg-config --libs libpulse-simple)

LDLIBS = -lpcap ${libpulse_LDLIBS}

# all: pcap2rtp pulse
all: pcap2rtp
pcap2rtp: pcap2rtp.o parser.o rtp.o pager.o util.o
pulse: pulse.o pcap2rtp.o rtp.o util.o

clean:
	$(RM) pcap2rtp pulse *.o

.PHONY: clean
