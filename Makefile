CFLAGS += -Wall -pedantic -std=gnu99 -O3
#CFLAGS += -DNDEBUG
LFLAGS = -lpthread -lsystemd

CC ?= gcc

ifneq ($(STATIC),)
	CFLAGS += -static
endif

.PHONY: all clean

all: picomdnsd

clean:
	$(RM) picomdnsd


picomdnsd:  mdns.c mdnsd.c
	$(CC) -o $@ $(CFLAGS) $^ $(LFLAGS)
