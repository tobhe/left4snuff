all: left4snuff

left4snuff: left4snuff.c
	cc $? -o $@

clean:
	rm -f left4snuff
