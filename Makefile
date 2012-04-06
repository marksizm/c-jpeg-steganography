all: utility

utility: crypto.c crypto.h lencode.c lencode.h rgen.c rgen.h rsrce.c rsrce.h steganolab.c steganolab.h utility.c
	gcc crypto.c lencode.c rgen.c rsrce.c steganolab.c utility.c -lcrypto -ljpeg -o utility

clean:
	rm utility || true


