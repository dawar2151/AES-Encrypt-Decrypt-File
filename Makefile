all: compiler
compiler: 
	gcc aes.c -o aes -lm -std=c99 
clean: 
	rm aes
