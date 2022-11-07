libelf.so: libelf.c libelf.h
	gcc -shared -fPIC -Wall -o $@ $<