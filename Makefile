CC=cc

CFLAGS+=-D_GNU_SOURCE
CFLAGS+=-O3
CFLAGS+=-Wall -Wextra

all: left4snuff

left4snuff: left4snuff.c
	${CC} ${CFLAGS} $? -o $@

.PHONY:clean
clean:
	rm -f left4snuff
