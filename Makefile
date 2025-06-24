source = src/main.c
target = crypt
cflags = -Wextra -Wall -O3
flags = -lssl -lcrypto

.PHONY: build

build:
	gcc -o $(target) $(source) $(cflags) $(flags)

clean:
	rm main
