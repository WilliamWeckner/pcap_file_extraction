CC=gcc -Wno-discarded-qualifiers -o
CFLAGS=-lpcap

extract_file:extract_file.c
	${CC} extract_file extract_file.c ${CFLAGS}

clean:
	rm extract_file
