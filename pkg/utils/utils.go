package utils

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

func PasswordPrompt() string {
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		os.Exit(1)
	}
	fmt.Println("\nPassword completed")
	return string(password)
}

func ReadInput(prompt string) []byte {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	}
	return input[:len(input)-1] // Remove the newline character
}
