CC=g++
CFLAGS=-g3 -ggdb -O3 -Wall -Wextra -Wno-unused
RSA=rsa.cpp
AES=aes.cpp
SALSA=salsa.cpp
BINS=rsa aes salsa
all: clean RSA AES SALSA

RSA:
	$(CC) $(CFLAGS) -o rsa $(RSA) -lcryptopp

AES:
	$(CC) $(CFLAGS) -o aes $(AES) -lcryptopp

SALSA:
	$(CC) $(CFLAGS) -o salsa $(SALSA) -lcryptopp

clean:
	@echo " [CLN] Removing binary files"
	@rm -f $(BINS)
