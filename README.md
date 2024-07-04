# OnionCrypt

OnionCrypt is a multi-layer encryption and decryption tool that provides secure data protection using AES-CBC encryption. It allows users to encrypt data multiple times with different passwords, creating layers of security similar to an onion's structure.

## Features

- Multi-layer encryption and decryption
- Password hints for each encryption layer
- AES-CBC encryption with PBKDF2 key derivation
- Command-line interface for easy usage
- Base64 encoding for encrypted output

## Installation

To install OnionCrypt, make sure you have Go installed on your system, then run:

```
go get github.com/schwartx/onion-crypt
```

## Building from Source

If you prefer to build the project from source, follow these steps:

1. Clone the repository:
   ```
   git clone https://github.com/schwartx/onion-crypt.git
   cd onion-crypt
   ```

2. Build the project:
   ```
   go build -o onion-crypt ./cmd/main.go
   ```

   This will create an executable named `onion-crypt` in your current directory.

3. (Optional) To install the built binary to your GOPATH's bin directory:
   ```
   go install ./cmd/main.go
   ```

## Usage

### Encryption

To encrypt data:

```
onion-crypt -enc
```

You will be prompted to enter the content you want to encrypt, followed by a series of password and hint inputs for each layer of encryption. Enter an empty password to finish the encryption process.

### Decryption

To decrypt data:

```
onion-crypt
```

You will be prompted to enter the Base64 encoded encrypted content, followed by the password for each layer. The program will display hints (if available) for each layer.

## Security Considerations

- OnionCrypt uses AES-CBC encryption, which is considered secure when properly implemented.
- PBKDF2 is used for key derivation, adding protection against brute-force attacks.
- The security of your data depends on the strength of your passwords. Use strong, unique passwords for each layer.
- Encrypted data is Base64 encoded, making it safe for storage and transmission in text format.

## Contributing

Contributions to OnionCrypt are welcome! Please feel free to submit pull requests, create issues, or suggest improvements.

## License

This project is licensed under the Creative Commons CC0 1.0 Universal License. This means you can copy, modify, distribute and perform the work, even for commercial purposes, all without asking permission.

For more information, please see the full license text in the LICENSE file or visit:
https://creativecommons.org/publicdomain/zero/1.0/

## Disclaimer

This tool is provided as-is, without any warranties or conditions of any kind, either express or implied, including without limitation any implied warranties or conditions of title, fitness for a particular purpose, merchantability or non-infringement.
