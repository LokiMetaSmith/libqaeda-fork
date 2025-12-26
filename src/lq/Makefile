OBJS := $(patsubst %.c,%.o,$(filter-out main.c,$(wildcard *.c)))
INCLUDES := -I.. -I../aux/include
CFLAGS +=  $(INCLUDES) -Wall -DRERR -fPIC
LIBS := ../asn1/defs_asn1_tab.o -L../aux/lib -llash

LDFLAGS += $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

all: $(OBJS)

clean:
	rm -vf *.o

.PHONY: clean
