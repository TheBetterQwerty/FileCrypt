#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_PATH 2096
#define AES_ENC 256
#define IV_SIZE 16

void handle_errors(const char *msg) {
	fprintf(stderr, "[!] Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

int get_key(char* key) {
	int cap = 16 * sizeof(char), len = 0;

	printf("[+] Enter Master Password: ");
	char* str = (char*) malloc(cap);
	if (!str) {
		fprintf(stderr, "[!] Error allocating memory!\n");
		return 1;
	}

	char c;
	while ((c = getchar() != '\n') && c != EOF) {
		if (len + 1 >= cap) {
			cap *= 2;
			char* temp = (char*) realloc(str, cap);
			if (!temp) {
				fprintf(stderr, "[!] Error allocating memory!\n");
				return 1;
			}

			str = temp;
			temp = NULL;
		}

		str[len++] = c;
	}

	str[len] = '\0';

	SHA256((const unsigned char*) str, len, (unsigned char*) key);

	free(str);
	return 0;
}

void encrypt_file(const char* filename, const unsigned char* key) {
	FILE* fptr = fopen(filename, "rb+");
	if (!fptr) {
		fprintf(stderr, "[!] %s\n", strerror(errno));
		return;
	}

	fseek(fptr, 0, SEEK_END);
	size_t size = ftell(fptr) * sizeof(char);
	fseek(fptr, 0, SEEK_SET);

	if (size <= 0) {
		fprintf(stderr, "[!] Empyty file!\n");
		fclose(fptr);
		return;
	}

	char* buffer = (char*) malloc(size);
	if (!buffer) {
		fprintf(stderr, "[!] Error allocating memory!\n");
		fclose(fptr);
		return;
	}

	if (size != fread(buffer, 1, size, fptr)) {
		fprintf(stderr, "[!] Error reading from file\n");
		fclose(fptr);
		free(buffer);
		return;
	}

	unsigned char* ciphertext = malloc(size + 16);
	if (!ciphertext) {
		fprintf(stderr, "[!] Error allocating memory!\n");
		fclose(fptr);
		free(buffer);
		return;
	}

	unsigned char iv[IV_SIZE];
	if (!RAND_bytes(iv, IV_SIZE))
		handle_errors("Randbyte failed");

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors("EVP_CIPHER_CTX_new");

    int len = 0, ciphertext_len = 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors("EVP_EncryptInit_ex");

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*) buffer, (int) size))
        handle_errors("EVP_EncryptUpdate");

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_errors("EVP_EncryptFinal_ex");

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

	fseek(fptr, 0, SEEK_SET);
	if (IV_SIZE != fwrite(iv, 1, IV_SIZE, fptr)) {
		fprintf(stderr, "[!] Error writting iv to file!\n");
		fclose(fptr);
		free(ciphertext);
		free(buffer);
		return;
	}

	if (ciphertext_len != (int) fwrite(ciphertext, 1, ciphertext_len, fptr)) {
		fprintf(stderr, "[!] Error writting encrypted to file!\n");
		fclose(fptr);
		free(ciphertext);
		free(buffer);
		return;
	}

	if (0 != ftruncate(fileno(fptr), IV_SIZE + ciphertext_len)) {
        fprintf(stderr, "[!] Failed to truncate file\n");
		fclose(fptr);
		free(ciphertext);
		free(buffer);
		return;
	}

	// cleanup
	fclose(fptr);
	free(ciphertext);
	free(buffer);

	printf("[+] Encrypted %s\n", filename);
}

void decrypt_file(const char* filename, const unsigned char* key) {
	FILE* fptr = fopen(filename, "rb+");
	if (!fptr) {
		fprintf(stderr, "[!] %s\n", strerror(errno));
		return;
	}

	fseek(fptr, 0, SEEK_END); // go to end of file
	size_t file_size = ftell(fptr) * sizeof(char);
	fseek(fptr, 0, SEEK_SET); // go to start of file

	if (file_size <= 0) {
		fprintf(stderr, "[!] %s a empty file\n", filename);
		fclose(fptr);
		return;
	}

	char* buffer = (char*) malloc(file_size);
	if (!buffer) {
		fprintf(stderr, "[!] Error allocating memory!\n");
		fclose(fptr);
		return;
	}

	if (file_size != fread(buffer, 1, file_size, fptr)) {
		fprintf(stderr, "[!] Error reading from file\n");
		fclose(fptr);
		free(buffer);
		return;
	}

	unsigned char iv[IV_SIZE];
	memcpy(iv, buffer, IV_SIZE);

	char* buffer_offset = buffer + IV_SIZE; // move pointer to start of the message

	unsigned char* out = (unsigned char*) malloc(file_size);
	if (!out) {
		free(buffer);
		fclose(fptr);
		fprintf(stderr, "[!] Error allocating memory!\n");
		return;
	}

	// Decryption Starts
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		free(out);
		free(buffer);
		fclose(fptr);
		handle_errors("Evp_cipher_ctx_new()");
	}

	int len = 0, plaintext_len = 0;

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		free(out);
		free(buffer);
		fclose(fptr);
		handle_errors("DecryptInit");
	}

	if (1 != EVP_DecryptUpdate(ctx, out, &len, (const unsigned char*) buffer_offset, file_size - IV_SIZE)) {
		free(buffer);
		free(out);
		fclose(fptr);
		handle_errors("EVP_DecryptUpdate");
	}

	plaintext_len = len;

	if (1 != EVP_DecryptFinal_ex(ctx, out + len, &len)) {
		free(buffer);
		free(out);
		fclose(fptr);
		handle_errors("EVP_DecryptFinal_ex");
	}

	plaintext_len += len;

	fseek(fptr, 0, SEEK_SET);
	if ((unsigned long) plaintext_len != fwrite(out, 1, plaintext_len, fptr)) {
		free(buffer);
		free(out);
		fclose(fptr);
		handle_errors("fwrite");
	}

	if (0 != ftruncate(fileno(fptr), plaintext_len)) {
		free(buffer);
		free(out);
		fclose(fptr);
		handle_errors("ftruncate");
	}

	EVP_CIPHER_CTX_free(ctx);
	free(buffer);
	free(out);
	fclose(fptr);

	printf("[+] Decrypted %s\n", filename);
}

void iter_folder(const char* path, const char* key, int enc) {
	struct stat path_stat;
	if (0 != stat(path, &path_stat)) {
		fprintf(stderr, "[!] %s\n", strerror(errno));
		return;
	}

	if (S_ISREG(path_stat.st_mode)) {
		if (enc) {
			encrypt_file(path, (const unsigned char*) key);
			return;
		}
		decrypt_file(path, (const unsigned char*) key);
		return;
	}

	if (!S_ISDIR(path_stat.st_mode)) {
		return;
	}

	DIR* dir = opendir(path);
	if (!dir) {
		fprintf(stderr, "[!] %s\n", strerror(errno));
		return;
	}

	struct dirent* entry;
	while ((entry = readdir(dir)) != NULL) {
		char file[MAX_PATH];

		if (!strncmp(entry->d_name, ".", 1) || !strncmp(entry->d_name, "..", 2)) continue;

		snprintf(file, MAX_PATH, "%s/%s", path, entry->d_name);

		struct stat _path_stat;
		if (0 != lstat(file, &_path_stat)) {
			fprintf(stderr, "[!] %s\n", strerror(errno));
			continue;
		}

		if (S_ISLNK(_path_stat.st_mode)) {
			continue;
		}

		if (S_ISDIR(_path_stat.st_mode)) {
			iter_folder(file, key, enc);
		}

		if (S_ISREG(_path_stat.st_mode)) {
			if (enc) {
				encrypt_file(file, (const unsigned char*) key);
				continue;
			}
			decrypt_file(file, (const unsigned char*) key);
		}
	}

	closedir(dir);
}

void print_help(const char* prog_name) {
    printf("Usage:\n");
    printf("  %s [option] <folder>\n\n", prog_name);
    printf("Options:\n");
    printf("  -e, --encrypt <folder>   Encrypt all files in the specified folder\n");
    printf("  -d, --decrypt <folder>   Decrypt all files in the specified folder\n");
    printf("  -h, --help               Show this help message and exit\n\n");
    printf("Examples:\n");
    printf("  %s --encrypt /path/to/folder\n", prog_name);
    printf("  %s -d /path/to/folder\n", prog_name);
}

int main(int args, char** argv) {
	if (args < 2) {
		printf("[?] Missing arguments. Try '%s --help' for more info\n", argv[0]);
		return 1;
	}

	char key[SHA256_DIGEST_LENGTH];

	for (int i = 0; i < args; i++) {
		if ((strncmp(argv[i], "--help", 6) == 0) || (strncmp(argv[i], "-h", 2) == 0)) {
			print_help(argv[0]);
			return 0;
		}

		if ((strncmp(argv[i], "--encrypt", 9) == 0) || (strncmp(argv[i], "-e", 2) == 0)) {
			if ( i + 1 >= args) {
				printf("[?] Missing argument for %s!\n", argv[i]);
				break;
			}

			if (get_key(key)) {
				return 1;
			}

			iter_folder(argv[i + 1], (const char*) key, 1);
			break;
		}

		if ((strncmp(argv[i], "--decrypt", 9) == 0) || (strncmp(argv[i], "-d", 2) == 0)) {
			if ( i + 1 >= args) {
				printf("[?] Missing argument for %s!\n", argv[i]);
				break;
			}

			if (get_key(key)) {
				return 1;
			}

			iter_folder(argv[i + 1], (const char*) key, 0);
			break;
		}
	}

	return 0;
}
