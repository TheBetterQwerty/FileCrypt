#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_PATH	2096
#define AES_ENC		256
#define IV_SIZE		16
#define CHUNK_SIZE	64 * 1024

unsigned char magic_cookie[] = {0xDE, 0xAD, 0xBE, 0xEF}; // 0xDEADBEEF
size_t magic_cookie_sz = sizeof(magic_cookie) / sizeof(magic_cookie[0]);
char* output_path = NULL;
char* input_path = NULL;

void handle_errors(const char *msg) {
	fprintf(stderr, "[!] Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

int hashcmp(const uint8_t* hash_t, const uint8_t* hash_tt) {
	uint8_t res = 0;
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		res |= hash_t[i] ^ hash_tt[i];
	}

	return res;
}

int get_key(const char* buf, char* key) {
	size_t cap = 16 * sizeof(char), len = 0;
	char c;

	fprintf(stdout, "%s ", buf);
	char* str = (char*) malloc(cap);
	if (!str) {
		fprintf(stderr, "[!] Error allocating memory!\n");
		return 1;
	}

	struct termios old, new;

	tcgetattr(STDIN_FILENO, &old);
	new = old;
	new.c_lflag &= ~(ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &new);

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

	tcsetattr(STDIN_FILENO, TCSANOW, &old);

	SHA256((const unsigned char*) str, len, (unsigned char*) key);

	memset(str, 0, len); // to prevent RAM dumps
	free(str);

	printf("\n");
	return 0;
}

void mkdir_all(const char* path) {
	char dir[MAX_PATH];
	struct stat statbuf;

	char* start = (char*) path;
	for (int i = 0; start[i] != '\0'; i++) {
		if ((start[i] == '/') && (i - 1 >= 0)) {
			memcpy(dir, start, i);
			dir[i] = '\0';

			if (stat(dir, &statbuf) == 0) {
				continue;
			}

			if (mkdir(dir, 0755)) { // rwxr-xr-x
				return;
			}
		}
	}
}

int serialize_path(const char* current_file, char* output_file) {
	int input_dir_size = strlen(input_path);
	int output_file_size = strlen(output_path);

	if (strncmp(current_file, input_path, input_dir_size) != 0) {
		return 1;
	}

	const char* relative = current_file + input_dir_size;
	int written = snprintf(output_file, MAX_PATH, "%s%s", output_path, relative);

	return written >= 0 && written < output_file_size; // 0
}

void decrypt_file(const char* filename, const char* outfile, const unsigned char* key) {
	FILE* fptr = fopen(filename, "rb");
	if (!fptr) {
		fprintf(stderr, "[!] Error: %s\n", strerror(errno));
		return;
	}

	fseek(fptr, 0, SEEK_END);
	size_t size = ftell(fptr) * sizeof(char);
	fseek(fptr, 0, SEEK_SET);

	if (size == 0) {
		fclose(fptr);
		return;
	}

	char mgc_cookie[magic_cookie_sz];

	if (magic_cookie_sz != fread(mgc_cookie, 1, magic_cookie_sz, fptr)) {
		fprintf(stderr, "[!] Error: Reading from headers %s file\n", filename);
		fclose(fptr);
		return;
	}

	if (0 != memcmp(mgc_cookie, magic_cookie, magic_cookie_sz)) {
		fprintf(stdout, "Skipping %s as it isn't encrypted\n", filename);
		fclose(fptr);
		return;
	}

	unsigned char iv[IV_SIZE];

	if (IV_SIZE != fread(iv, 1, IV_SIZE, fptr)) {
		fprintf(stderr, "[!] Error: Reading from nonce %s file\n", filename);
		fclose(fptr);
		return;
	}

	FILE* out_ptr = fopen(outfile, "wb");
	if (!out_ptr) {
		fprintf(stderr, "[!] %s\n", strerror(errno));
		fclose(fptr);
		return;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		fclose(fptr);
		fclose(out_ptr);
		handle_errors("Evp_cipher_ctx_new()");
	}

	int len = 0, plaintext_len = 0;

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		fclose(fptr);
		fclose(out_ptr);
		handle_errors("DecryptInit");
	}

	unsigned char buffer[CHUNK_SIZE];
	unsigned char plaintext[CHUNK_SIZE];
	ssize_t nbytes = 0;

	do {
		nbytes = fread(buffer, 1, size, fptr);

		if (nbytes < 0) {
			fprintf(stderr, "[!] Error: Reading file %s\n", filename);
			return;
		}

		if (nbytes == 0) break;

		if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, buffer, nbytes)) {
			fclose(fptr);
			fclose(out_ptr);
			handle_errors("EVP_DecryptUpdate");
		}

		plaintext_len = len;

		if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
			fclose(fptr);
			fclose(out_ptr);
			handle_errors("EVP_DecryptFinal_ex");
		}

		plaintext_len += len;

		if ((unsigned long) plaintext_len != fwrite(plaintext, 1, plaintext_len, out_ptr)) {
			fclose(out_ptr);
			fclose(fptr);
			handle_errors("fwrite");
		}
	} while (nbytes > 0);

	fclose(out_ptr);
	fclose(fptr);
	EVP_CIPHER_CTX_free(ctx);
	printf("[+] File %s was decrypted as stored at %s\n", filename, outfile);
}

void encrypt_file(const char* filename, const char* outfile, const unsigned char* key) {
	FILE* fptr = fopen(filename, "rb");
	if (!fptr) {
		fprintf(stderr, "[!] Error: %s\n", strerror(errno));
		return;
	}

	// Join outfile/filename smth like that
	FILE* out_ptr = fopen(outfile, "wb");
	if (!out_ptr) {
		fprintf(stderr, "[!] %s\n", strerror(errno));
		return;
	}

	fseek(fptr, 0, SEEK_END);
	size_t size = ftell(fptr) * sizeof(char);
	fseek(fptr, 0, SEEK_SET);

	if (size <= 0) {
		fclose(fptr);
		return;
	}

	unsigned char buffer[CHUNK_SIZE];
	unsigned char ciphertext[CHUNK_SIZE + IV_SIZE];
	ssize_t nbytes;

	unsigned char iv[IV_SIZE];
	if (!RAND_bytes(iv, IV_SIZE)) handle_errors("Randbyte failed");

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors("EVP_CIPHER_CTX_new");

	int len = 0, ciphertext_len = 0;
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors("EVP_EncryptInit_ex");

	if (magic_cookie_sz != fwrite(magic_cookie, 1, magic_cookie_sz, out_ptr)) {
		fprintf(stderr, "[!] Error writting magic cookie to file!\n");
		fclose(fptr);
		fclose(out_ptr);
		return;
	}

	if (IV_SIZE != fwrite(iv, 1, IV_SIZE, out_ptr)) {
		fprintf(stderr, "[!] Error writting iv to file!\n");
		fclose(fptr);
		fclose(out_ptr);
		return;
	}

	do {
		nbytes = fread(buffer, 1, size, fptr);

		if (nbytes < 0) {
			fprintf(stderr, "[!] Error: Reading file %s\n", filename);
			return;
		}

		if (nbytes == 0) break;

		if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, (int) nbytes))
			handle_errors("EVP_EncryptUpdate");

		ciphertext_len = len;

		if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
			handle_errors("EVP_EncryptFinal_ex");

		ciphertext_len += len;

		if (ciphertext_len != (int) fwrite(ciphertext, 1, ciphertext_len, out_ptr)) {
			fprintf(stderr, "[!] Error writting encrypted to file!\n");
			fclose(fptr);
			fclose(out_ptr);
			return;
		}

	} while (nbytes > 0);

	EVP_CIPHER_CTX_free(ctx);
	fclose(fptr);
	fclose(out_ptr);
	printf("[+] File %s was encrypted as stored at %s\n", filename, outfile);
}

void iter_folder(const char* path, const char* outpath, const unsigned char* key, int enc) {
	struct stat path_stat;
	if (0 != lstat(path, &path_stat)) {
		fprintf(stderr, "[!] %s\n", strerror(errno));
		return;
	}

	if (S_ISREG(path_stat.st_mode)) {
		mkdir_all(outpath);
		enc ? encrypt_file(path, outpath, key) : decrypt_file(path, outpath, key);
		return;
	}

	if (!S_ISDIR(path_stat.st_mode)) return;

	DIR* dir = opendir(path);
	if (!dir) {
		fprintf(stderr, "[!] %s\n", strerror(errno));
		return;
	}

	struct dirent* entry;
	while ((entry = readdir(dir)) != NULL) {
		char file[MAX_PATH];

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;

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
			iter_folder(file, outpath, key, enc);
		}

		if (S_ISREG(_path_stat.st_mode)) {
			char output_file[MAX_PATH];
			if (serialize_path(file, output_file)) continue;
			mkdir_all(output_file);
			enc ? encrypt_file(file, output_file, key) : decrypt_file(file, output_file, key);
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

	unsigned char key[SHA256_DIGEST_LENGTH], _key[SHA256_DIGEST_LENGTH];
	int flag = -1;

	for (int i = 1; i < args; i++) {
		if ((strcmp(argv[i], "--help") == 0) || (strcmp(argv[i], "-h") == 0)) {
			print_help(argv[0]);
			return 0;
		}

		if ((strcmp(argv[i], "--encrypt") == 0) || (strcmp(argv[i], "-e") == 0)) {
			flag = 1;

			if ( i + 1 >= args) {
				printf("[?] Missing argument for %s!\n", argv[i]);
				break;
			}

			if (get_key("[+] Enter master key: ", (char*) key)) {
				return 1;
			}

			if (get_key("[+] Enter master key again: ", (char*) _key)) {
				return 1;
			}

			if (hashcmp((const uint8_t*) key, (const uint8_t*) _key)) {
				fprintf(stderr, "[!] Given key's don't match!\n");
				return 1;
			}

			input_path = argv[i + 1];
			continue;
		}

		if ((strcmp(argv[i], "--decrypt") == 0) || (strcmp(argv[i], "-d") == 0)) {
			flag = 0;

			if ( i + 1 >= args) {
				printf("[?] Missing argument for %s!\n", argv[i]);
				break;
			}

			if (get_key("[+] Enter master key ->", (char*) key)) {
				return 1;
			}

			input_path = argv[i + 1];
			continue;
		}

		if ((strcmp(argv[i], "--output") == 0) || (strcmp(argv[i], "-o") == 0)) {
			if (i + 1 >= args) {
				printf("[?] Missing argument for %s!\n", argv[i]);
				break;
			}

			output_path = argv[i+1];
			continue;
		}
	}

	if (!input_path || !output_path) {
		fprintf(stderr, "[!] Error: Please input a directory and a output directory\n");
		return 1;
	}


	switch (flag) {
		case -1:
			printf("[?] Invalid argument \'");
			for (int i = 1; i < args; i++)
				printf("%s", argv[i]);
			printf("\'. Try '%s --help' for more info\n", argv[0]);
			break;
		case 0:
			// Decrypt
			iter_folder((const char*) input_path, output_path, key, flag);
			break;
		case 1:
			// Encrypt
			iter_folder((const char*) input_path, output_path, key, flag);
			break;
	}

	return 0;
}
