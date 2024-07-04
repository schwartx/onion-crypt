package layercrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

var (
	ErrGeneratingSalt    = errors.New("error generating salt")
	ErrCreatingCipher    = errors.New("error creating cipher")
	ErrInvalidBlockSize  = errors.New("ciphertext is not a multiple of the block size")
	ErrInvalidPaddingLen = errors.New("invalid padding length")
)

// Encryptor handles core encryption operations
type Encryptor struct{}

// Encrypt performs the encryption operation
func (e *Encryptor) Encrypt(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGeneratingSalt, err)
	}

	key, iv := e.deriveKeyAndIV([]byte(password), salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCreatingCipher, err)
	}

	paddedPlaintext := e.addPadding(plaintext)

	ciphertext := make([]byte, len(paddedPlaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	result := make([]byte, len(saltPrefix)+len(salt)+len(ciphertext))
	copy(result, saltPrefix)
	copy(result[len(saltPrefix):], salt)
	copy(result[len(saltPrefix)+len(salt):], ciphertext)

	return result, nil
}

func (e *Encryptor) deriveKeyAndIV(password, salt []byte) (key, iv []byte) {
	keyAndIV := pbkdf2.Key(password, salt, 10000, keySize+ivSize, sha256.New)
	return keyAndIV[:keySize], keyAndIV[keySize:]
}

func (e *Encryptor) addPadding(data []byte) []byte {
	padLen := aes.BlockSize - (len(data) % aes.BlockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// Decrypt performs the decryption operation
func (e *Encryptor) Decrypt(ciphertext []byte, password string) ([]byte, error) {
	if len(ciphertext) < len(saltPrefix)+saltSize {
		return nil, fmt.Errorf("%w: insufficient length", ErrInvalidCiphertext)
	}

	salt := ciphertext[len(saltPrefix) : len(saltPrefix)+saltSize]
	key, iv := e.deriveKeyAndIV([]byte(password), salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCreatingCipher, err)
	}

	if len(ciphertext[len(saltPrefix)+saltSize:])%aes.BlockSize != 0 {
		return nil, ErrInvalidBlockSize
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext)-len(saltPrefix)-saltSize)
	mode.CryptBlocks(plaintext, ciphertext[len(saltPrefix)+saltSize:])

	return e.removePadding(plaintext)
}

func (e *Encryptor) removePadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrInvalidPadding
	}
	padLen := int(data[len(data)-1])
	if padLen > len(data) {
		return nil, ErrInvalidPaddingLen
	}
	return data[:len(data)-padLen], nil
}
