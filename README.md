# zStash

`zStash` is a command-line tool for securely encrypting and decrypting files using AES-GCM encryption with password-based key derivation (PBKDF2).

## Features

- **File Encryption and Decryption**: Encrypt files with AES-GCM and decrypt them back to their original form.
- **Password Management**: Set a password that is used to derive the encryption key.
- **Secure Storage**: Encrypted files are stored in a secure directory within the user's home directory under .zstash_files.

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/zstash.git
   cd zstash
   ```

2. Build the project:
   ```sh
   cargo build --release
   ```

3. Run the project:
   ```sh
   cargo run -- [COMMAND] [FILE]
   ```

## Usage

### Encrypt a File

To encrypt a file, use the `encrypt` command followed by the file name:

```sh
cargo run -- encrypt <file_path>
```

Example:

```sh
cargo run -- encrypt example.txt
```

This will prompt you to enter your password. If the password is correct, the file will be encrypted and stored in a secure directory.

### Decrypt a File

To decrypt a file, use the `decrypt` command followed by the file name:

```sh
cargo run -- decrypt <file_path>
```

Example:

```sh
cargo run -- decrypt example.txt
```

This will prompt you to enter your password. If the password is correct, the file will be decrypted and saved in the current working directory.

### To get help

```sh
cargo run -- --help
```

In case of knowing how to use a particular command just use --help