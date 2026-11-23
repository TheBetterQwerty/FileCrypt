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
#define CHUNK_SIZE	(64 * 1024)

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
	EVP_CIPHER_CTX* ctx = NULL;
	FILE *fptr = fopen(filename, "rb"), *out_ptr = NULL;
	if (!fptr) {
		fprintf(stderr, "[!] Error: %s\n", strerror(errno));
		return;
	}

	unsigned char ciphertext[CHUNK_SIZE];
	unsigned char decrypted[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH]; 
	unsigned char mgc_cookie_check[4] = { 0 };
	unsigned char nonce[12] = { 0 }, tag[16] = {0 };

	char finished = 0x0;
		
	if (fseek(fptr, 0, SEEK_END) != 0) {
		goto cleanup;
	}
	
	size_t size = ftell(fptr);

	if (size < 32) {
		fprintf(stderr, "[?] Skipping not a encrypted file\n");
		goto cleanup;
	}

	if (fseek(fptr, -16, SEEK_END) != 0) {
		goto cleanup;
	}

	if (16 != fread(tag, 1, 16, fptr)) {
		fprintf(stderr, "[!] Error: %s\n", strerror(errno));
		goto cleanup;
	}

	size_t cipher_len = (size_t) size - 16 - 12 - 4; // Metadata size is 16 + 12 + 4
	uint64_t n_chunks = (cipher_len / CHUNK_SIZE) + 1;

	rewind(fptr);

	if (4 != fread(mgc_cookie_check, 1, 4, fptr)) {
		fprintf(stderr, "[!] Error: %s\n", strerror(errno));
		return;
	}
	
	if (memcmp(mgc_cookie_check, magic_cookie, 4)) {
		fprintf(stdout, "[?] Unencrypted file %s skipping it\n", outfile);
		return;
	}

	if (12 != fread(nonce, 1, 12, fptr)) {
		fprintf(stderr, "[!] Error: %s\n", strerror(errno));
		return;
	}

	// Setup AES stuff
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		fprintf(stderr, "[!] Error: %s\n", strerror(errno));
		goto cleanup;
	}

	if (EVP_DecryptInit_ex(
				ctx, 
				EVP_aes_256_gcm(),
				NULL,
				key,
				nonce
		) != 1
	) {
		goto cleanup;
	}

	out_ptr = fopen(outfile, "wb");
	if (!out_ptr) {
		fprintf(stderr, "[!] Error: %s\n", strerror(errno));
		goto cleanup;
	}
	
	size_t total_read = 0;
	int bytes_decry = 0;

	// Tag size 16
	uint64_t current_cnk = 0;
	while (total_read < cipher_len) { 
		size_t chunk = (cipher_len - total_read) > CHUNK_SIZE ? CHUNK_SIZE : (cipher_len - total_read);

		size_t nread = fread(ciphertext, 1, chunk, fptr);
		if (nread == 0) break;

		// decrypt the chunk
		if (1 != EVP_DecryptUpdate(
			ctx, 
			decrypted,
			&bytes_decry,
			ciphertext,
			nread
		)) {
			fprintf(stderr, "[!] Error: LMAO %s\n", strerror(errno));
			goto cleanup;
		}

		if (bytes_decry > 0 && (size_t) bytes_decry != fwrite(decrypted, 1, bytes_decry, out_ptr)) {
			fprintf(stderr, "[!] Error: Writting to file!\n");
			goto cleanup;
		}

		total_read += nread;

		printf("\r[#] Decrypting Chunk =======> (%ld/%ld)", ++current_cnk, n_chunks);
	}

	printf("\n");
	if (EVP_CIPHER_CTX_ctrl(
				ctx,
				EVP_CTRL_GCM_SET_TAG,
				16,
				tag
				) != 1) {
		goto cleanup;
	}

	if (1 != EVP_DecryptFinal_ex(ctx, decrypted, &bytes_decry)) {
		fprintf(stderr, "[!] Error: Authentication Failed\n");
		goto cleanup;
	}
	
	if (bytes_decry > 0 && (size_t) bytes_decry != fwrite(decrypted, 1, bytes_decry, out_ptr)) {
		fprintf(stderr, "[!] Error: Writting to file\n");
		goto cleanup;
	}
	
	finished = 0x01;
cleanup:
	if(ctx) EVP_CIPHER_CTX_free(ctx);
	if (fptr) fclose(fptr);
	if (out_ptr) fclose(out_ptr);
	if (finished) printf("[+] File %s was decrypted and stored at %s\n", filename, outfile);
}

void encrypt_file(const char* filename, const char* outfile, const unsigned char* key) {
	EVP_CIPHER_CTX* ctx = NULL;
	char finished = 0x0;

	if (!strcmp(filename, outfile)) {
		fprintf(stderr, "[!] Error: File names are same\n");
		return;
	}

	FILE *fptr = fopen(filename, "rb"), *outptr = NULL;
	if (!fptr) {
		fprintf(stderr, "[!] Error: %s\n", strerror(errno));
		return;
	}

	fseek(fptr, 0, SEEK_END);
	uint64_t n_chunks = (ftell(fptr) / CHUNK_SIZE) + 1;
	rewind(fptr);

	outptr = fopen(outfile, "wb");
	if (!outptr) {
		fprintf(stderr, "[!] Error: %s\n", strerror(errno));
		goto cleanup;
	}

	unsigned char buffer[CHUNK_SIZE];
	unsigned char nonce[12], tag[16];
	unsigned char encrypted_buffer[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];
	
	
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		fprintf(stderr, "[!] Error: %s\n", strerror(errno));
		goto cleanup;
	}

	if (RAND_bytes(nonce, 12) != 1 || 
		EVP_EncryptInit_ex(
			ctx, 
			EVP_aes_256_gcm(),
			NULL,
			key,
			nonce
		) != 1
	) {
		goto cleanup;
	}

	if (magic_cookie_sz != fwrite(magic_cookie, 1, magic_cookie_sz, outptr)) {
		fprintf(stderr, "[!] Error: writting into %s file\n", outfile);
		goto cleanup;
	}

	if (12 != fwrite(nonce, 1, 12, outptr)) {
		fprintf(stderr, "[!] Error: writting nonce into %s file\n", outfile);
		goto cleanup;
	}
	
	size_t nread = 0;
	int written = 0;
	uint64_t current_chk = 0;

	while ((nread = fread(buffer, 1, CHUNK_SIZE, fptr)) > 0) {
		if (1 != EVP_EncryptUpdate(ctx, encrypted_buffer, &written, buffer, (int)nread)) {
			fprintf(stderr, "[!] Error: EVP_EncryptUpdate\n");
			goto cleanup;
		}

		if ((size_t) written != fwrite(encrypted_buffer, 1, (size_t) written, outptr)) {
			fprintf(stderr, "[!] Error: writting to file\n");
			goto cleanup;
		}

		printf("\r[#] Encrypting Chunk ======================> (%ld/%ld)", ++current_chk, n_chunks);
	}

	printf("\n");

	if (ferror(fptr)) goto cleanup;

	if (1 != EVP_EncryptFinal_ex(ctx, encrypted_buffer, &written)) {
		fprintf(stderr, "[!] Error: EVP_EncryptFinal_ex\n");
		goto cleanup;
	}

	if (fwrite(encrypted_buffer, 1, (size_t)written, outptr) != (size_t)written) {
		fprintf(stderr, "[!] Error: Writting to file %d\n", __LINE__);
		goto cleanup;
	}

	// TAG and write to file
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1 || fwrite(tag, 1, 16, outptr) != 16) {
		fprintf(stderr, "[!] Error: Writting tag to file\n");
		goto cleanup;
	}

	finished = 0x01;

cleanup:
	if (ctx) EVP_CIPHER_CTX_free(ctx);
	if (fptr) fclose(fptr);
	if (outptr) fclose(outptr);
	if (finished) printf("[+] File %s was encrypted and stored at %s\n", filename, outfile);
	return;
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
