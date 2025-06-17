source = main.c 
target = main 
cflags = -Wextra -Wall -O3
flags = -lssl -lcrypto

.PHONY: build

build:
	gcc -o $(target) $(source) $(cflags) $(flags)

clean:
	rm main 
