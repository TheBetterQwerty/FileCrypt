#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_SIZE 32
#define AES_ENC 256
#define IV_SIZE 16

void handle_errors(const char *msg) {
	fprintf(stderr, "[!] Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

int get_key(char* key) {
	printf("[+] Enter Master Password: ");
	if (fgets(key, KEY_SIZE - 2, stdin) == NULL) {
		perror("[!] Error taking input!\n");
		return 1;
	}

	int len = (int) strlen(key);
	if (len < KEY_SIZE - 1) {
		memset(key, '@', (KEY_SIZE - 1 - len));
	}

	// just hash ts ig

	key[KEY_SIZE - 1] = '\0';
	return 0;
}

void encrypt_file(const char* filename, const unsigned char* key) {
	FILE* fptr = fopen(filename, "rb+");
	if (!fptr) {
		perror("[!] Error opening file\n");
		return;
	}

	fseek(fptr, 0, SEEK_END);
	long size = ftell(fptr) * sizeof(char);

	if (size <= 0) {
		perror("[!] Empyty file!\n");
		fclose(fptr);
		return;
	}

	fseek(fptr, 0, SEEK_SET);
	char* buffer = (char*) malloc(size);
	if (!buffer) {
		perror("[!] Error allocating memory!\n");
		fclose(fptr);
		return;
	}

	if (size != (long) fread(buffer, 1, size, fptr)) {
		perror("[!] Error reading from file\n");
		fclose(fptr);
		free(buffer);
		return;
	}

	unsigned char* ciphertext = malloc(size + 16);
	if (!ciphertext) {
		perror("[!] Error allocating memory!\n");
		fclose(fptr);
		free(buffer);
		return;
	}

	unsigned char iv[IV_SIZE];
	if (!RAND_bytes(iv, IV_SIZE))
		handle_errors("Randbyte failed");

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors("EVP_CIPHER_CTX_new");

    int len, ciphertext_len;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors("EVP_EncryptInit_ex");

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*) buffer, (int) size))
        handle_errors("EVP_EncryptUpdate");

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_errors("EVP_EncryptFinal_ex");

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

	for (int i = 0; i < 16; i++) {
		printf("%02x", iv[i]);
	}
	printf("\n");

	for (int i = 0; i < ciphertext_len; i++) {
		printf("%02x", ciphertext[i]);
	}
	printf("\n");

	fclose(fptr);
	free(ciphertext);
	free(buffer);
}

void decrypt_file(const char* filename) {}

int main(int args, char** argv) {
	if (args < 2) {
		perror("[!] Please enter a file name\n");
		return 1;
	}

	char key[KEY_SIZE];
	if (get_key(key)) {
		return 1;
	}

	for (int i = 0; i < args; i++) {
		if ((strncmp(argv[i], "--encrypt", 9) == 0) || (strncmp(argv[i], "-e", 9) == 0)) {
			if ( i + 1 >= args) {
				printf("[?] Missing argument for %s!\n", argv[i]);
				break;
			}

			// handle a directory too check if its a directory if error recvied ENOTDIR then loop over the directories
			printf("Enc\n");
			encrypt_file(argv[i + 1], (const unsigned char*) key);
			break;
		}

		if ((strncmp(argv[i], "--decrypt", 9) == 0) || (strncmp(argv[i], "-d", 9) == 0)) {
			if ( i + 1 >= args) {
				printf("[?] Missing argument for %s!\n", argv[i]);
				break;
			}

			decrypt_file(argv[i + 1]);
			break;
		}
	}

	return 0;
}
