INCLUDES := -I.. -I../aux/include `pkg-config --cflags libtasn1`
LIBS := `pkg-config --libs libtasn1`
LDFLAGS += $(LIBS)
CFLAGS +=  $(INCLUDES) -Wall

all: compile dynamic

generate_asn1: generate.c
	$(CC) $(CFLAGS) generate.c -o generate_asn1 $(LDFLAGS)

tasn.o: tasn.c
	$(CC) $(CFLAGS) -fPIC -c tasn.c -o tasn.o $(LDFLAGS)

defs_asn1_tab.c: generate_asn1
	if [ -x ./generate_asn1 ]; then ./generate_asn1; else echo "Skipping generation (tool missing)"; fi

defs_asn1_tab.o: defs_asn1_tab.c
	$(CC) $(CFLAGS) -c $< -o $@

compile: defs_asn1_tab.o tasn.o

clean:
	rm -vf *.o
	rm -vf *_tab.c
	rm -vf generate_asn1

dynamic:


.PHONY: clean
