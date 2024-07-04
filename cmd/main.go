package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/schwartx/onion-crypt/pkg/layercrypt"
	"github.com/schwartx/onion-crypt/pkg/utils"
)

func decrypt() {
	encodedCiphertext := utils.ReadInput("Enter Base64 encoded encrypted content: ")

	ciphertext, err := base64.StdEncoding.DecodeString(string(encodedCiphertext))
	if err != nil {
		fmt.Printf("Base64 decoding error: %v\n", err)
		os.Exit(1)
	}

	decryptor := &layercrypt.Decryptor{}
	content := layercrypt.Content{Payload: ciphertext}

	for {
		if content.Hint != "" {
			fmt.Printf("Password hint: %s\n", content.Hint)
		}

		password := utils.PasswordPrompt()
		if password == "" {
			fmt.Println("Empty password entered. Exiting...")
			return
		}

		decryptedData, err := decryptor.Decrypt(content.Payload, password)
		if err != nil {
			fmt.Printf("Decryption failed: %v\n", err)
			continue
		}

		if err := layercrypt.Deserialize(decryptedData, &content); err != nil {
			fmt.Println("Decryption successful, but unable to parse. This might be the final plaintext content.")
			fmt.Printf("Decryption result:\n%s\nDecryption completed\n", decryptedData)
			return
		}

		if content.RemainingLayers == 0 {
			fmt.Printf("Decryption result:\n%s\nDecryption completed\n", content.Payload)
			return
		}

		fmt.Printf("Successfully decrypted one layer, %d layer(s) remaining, continuing to the next...\n", content.RemainingLayers)
	}
}

func encrypt() {
	content := layercrypt.Content{
		Payload:         utils.ReadInput("Enter content to encrypt: "),
		RemainingLayers: 0,
	}

	encryptor := &layercrypt.Encryptor{}

	for {
		password := utils.PasswordPrompt()
		if password == "" {
			fmt.Println("Empty password entered. Exiting...")
			break
		}

		serialData := content.Serialize()

		ciphertext, err := encryptor.Encrypt(serialData, password)
		if err != nil {
			fmt.Printf("Encryption failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Layer %d encrypted successfully.\n", content.RemainingLayers)

		hint := string(utils.ReadInput("Enter password hint (leave empty for 'no hint!'): "))
		if hint == "" {
			hint = "no hint!"
		}

		content = layercrypt.Content{
			Payload:         ciphertext,
			RemainingLayers: content.RemainingLayers + 1,
			Hint:            hint,
		}
	}

	encodedCiphertext := base64.StdEncoding.EncodeToString(content.Payload)
	fmt.Printf("Final encryption result:\n%s\nEncryption completed. Total layers encrypted: %d.\n", encodedCiphertext, content.RemainingLayers)
}

func main() {
	encryptFlag := flag.Bool("enc", false, "Use encryption mode")
	flag.Parse()

	if *encryptFlag {
		encrypt()
	} else {
		decrypt()
	}
}
