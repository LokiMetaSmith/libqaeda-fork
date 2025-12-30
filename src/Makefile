INCLUDES := -I. -I./aux/include
CFLAGS +=  $(INCLUDES) -Wall -DRERR -O2
#LIBOBJFILES = ./asn1/*.o ./*.o ./lq/*.o ./store/file.o ./mem/std.o ./io/std.o ./crypto/gcrypt.o
LIBOBJFILES = ./asn1/*.o ./*.o ./lq/*.o ./store/file.o ./mem/std.o ./io/std.o ./crypto/gcrypt.o ./aux/hashmap.c/hashmap.o ./aux/liblash/src/rerr/*.o ./aux/liblash/src/llog/*.o ./aux/liblash/src/endian/*.o ./aux/liblash/src/hex/*.o  ./aux/liblash/src/case/*.o ./aux/cwalk/build/CMakeFiles/cwalk.dir/src/cwalk.c.o

LIBOBJEMBED = ./asn1/*.o ./*.o ./lq/*.o ./store/file.o ./mem/std.o ./io/std.o ./crypto/gcrypt.o ./aux/hashmap.o ./aux/rerr.o ./aux/llog.o ./aux/endian.o ./aux/hex.o  ./aux/case.o ./aux/cwalk.o
LIBS := `pkg-config --libs libtasn1 libgcrypt` -L./aux/lib -llash -lcwalk

all: all-gpg
all-dummy: dummy
all-gpg: gpg

dev-lib: all
	#ar rcs liblq.a lq/config.o crypto/gcrypt.o store/file.o mem/std.o io/std.o debug.o aux/lib/libhashmap.a 
	ar rcs libqaeda.a $(LIBOBJFILES)
	#libtool --mode=link --tag=CC $(CC) -static -o libqaeda.a liblq.a ./aux/lib/liblash.a ./aux/lib/libcwalk.a

test-lib: dev-lib

core: aux asn1
	$(CC) $(CFLAGS) -c debug.c
	make -C lq

aux:
	make -C aux

asn1:
	make -C asn1 all

# Parallelized gpg target
gpg: mem_std io_std store_dummy crypto_gpg

# Parallelized dummy target
dummy: crypto_dummy mem_std io_std store_dummy

# Dependencies for parallel targets
mem_std: core
	make -C mem std

io_std: core
	make -C io std

store_dummy: core
	make -C store dummy

crypto_gpg: core
	make -C crypto gpg

crypto_dummy: core
	make -C crypto dummy

gpg-shared:
	make -C crypto gpg-shared

std: mem_std io_std store_dummy
	make -C lq

test: all test-lib 
	make -C test

coverage: export CFLAGS += -fprofile-arcs -ftest-coverage -DCOVERAGE_TEST
coverage: clean all test-lib
	make -C test coverage

clean:
	make -C asn1 clean
	make -C lq clean
	make -C test clean
	make -C mem clean
	make -C crypto clean
	rm -vf *.o *.a *.so

tools:
	make -C tools

#shared-gpg: core aux asn1 gpg
#	#make -C aux/liblash/src lib
#	$(CC) $(CFLAGS) -shared -o libqaeda.so $(LIBOBJEMBED)
shared:
	#make -C aux shared
	$(CC) $(CFLAGS) -shared -o libqaeda.so $(LIBOBJEMBED)
#	$(CC) $(CFLAGS) -shared -o libqaeda.so libqaeda.a
			

.PHONY: clean asn1 aux core mem_std io_std store_dummy crypto_gpg crypto_dummy coverage
