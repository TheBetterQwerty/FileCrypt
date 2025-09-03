# File Encryption Utility

A lightweight command-line utility written in C for encrypting and decrypting files in a directory using AES encryption with a SHA-256-derived key.

## Features

- AES-based encryption and decryption
- SHA-256 key derivation
- Recursive folder processing
- Simple command-line interface
- Minimal external dependencies

## Requirements

- GCC or Clang
- OpenSSL development libraries (`libssl-dev` on Debian-based systems)

## Build Instructions

```bash
make
````

This will compile the project and produce the `main` executable.

## Usage

```bash
./main [option] <folder>
```

### Options

* `-e, --encrypt <folder>`: Encrypt all files in the specified folder
* `-d, --decrypt <folder>`: Decrypt all files in the specified folder
* `-h, --help`: Display usage information

### Examples

Encrypt only a file:

```bash
./main --encrypt /path/to/file
```

Decrypt only a file:

```bash
./main --decrypt /path/to/file
```

Encrypt all files in a folder:

```bash
./main --encrypt /path/to/folder
```

Decrypt all files in a folder:

```bash
./main -d /path/to/folder
```

## Key Derivation

The encryption key is derived using SHA-256 from user input at runtime. This key is used consistently across encryption and decryption processes.

## Notes

* Only regular files are encrypted; directories and symbolic links are ignored.
