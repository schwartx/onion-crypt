package layercrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltPrefix = "Salted__"
	saltSize   = 8
	keySize    = 32
	ivSize     = 16
)

var (
	ErrInvalidCiphertext = errors.New("invalid ciphertext format")
	ErrInvalidPrefix     = errors.New("invalid ciphertext prefix")
	ErrEmptyData         = errors.New("empty data")
	ErrInvalidPadding    = errors.New("invalid padding")
)

// Decryptor handles core decryption operations
type Decryptor struct{}

// Decrypt performs the decryption operation
func (d *Decryptor) Decrypt(ciphertext []byte, password string) ([]byte, error) {
	if len(ciphertext) < len(saltPrefix)+saltSize {
		return nil, ErrInvalidCiphertext
	}

	if string(ciphertext[:len(saltPrefix)]) != saltPrefix {
		return nil, ErrInvalidPrefix
	}

	salt := ciphertext[len(saltPrefix) : len(saltPrefix)+saltSize]
	ciphertext = ciphertext[len(saltPrefix)+saltSize:]

	key, iv := d.deriveKeyAndIV([]byte(password), salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return d.removePadding(plaintext)
}

func (d *Decryptor) deriveKeyAndIV(password, salt []byte) (key, iv []byte) {
	keyAndIV := pbkdf2.Key(password, salt, 10000, keySize+ivSize, sha256.New)
	return keyAndIV[:keySize], keyAndIV[keySize:]
}

func (d *Decryptor) removePadding(data []byte) ([]byte, error) {
	dataLen := len(data)
	if dataLen == 0 {
		return nil, ErrEmptyData
	}
	padding := int(data[dataLen-1])
	if padding > dataLen {
		return nil, ErrInvalidPadding
	}
	return data[:dataLen-padding], nil
}
