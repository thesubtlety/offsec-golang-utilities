// https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/ShellcodeUtils/main.go

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/argon2"
)

func decryptAES(encryptionType, salt, key, inputNonce string, shellcode []byte) (decryptedBytes []byte) {
	switch strings.ToUpper(encryptionType) {
	case "AES256":
		// https://github.com/gtank/cryptopasta/blob/master/encrypt.go
		//fmt.Printf("[-]AES256 decrypting input file\n")

		// I leave it up to the operator to use the password + salt for decryption or just the Argon2 key
		if salt == "" {
			//fmt.Println("[!]A 32-byte salt in hex format must be provided with the -salt argument to decrypt AES256 input file")
		}
		if len(salt) != 64 {
			//fmt.Println("[!]A 32-byte salt in hex format must be provided with the -salt argument to decrypt AES256 input file")
			//fmt.Println(fmt.Sprintf("[!]A %d byte salt was provided", len(salt)/2))
		}

		saltDecoded, errSaltDecoded := hex.DecodeString(salt)
		if errSaltDecoded != nil {
			//fmt.Println(fmt.Sprintf("[!]%s", errSaltDecoded.Error()))
		}
		//fmt.Println("[-]Argon2 salt (hex): %x", saltDecoded)

		aesKey := argon2.IDKey([]byte(key), saltDecoded, 1, 64*1024, 4, 32)
		//fmt.Println("[-]AES256 key (hex): %x", aesKey)

		cipherBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			//fmt.Println(fmt.Sprintf("[!]%s", err.Error()))
		}

		gcm, _ := cipher.NewGCM(cipherBlock)
		if err != nil {
			//fmt.Println(fmt.Sprintf("[!]%s", errGcm.Error()))
		}

		if len(shellcode) < gcm.NonceSize() {
			//fmt.Println("[!]Malformed ciphertext is larger than nonce")
		}

		if len(inputNonce) != gcm.NonceSize()*2 {
			//fmt.Println("[!]A nonce, in hex, must be provided with the -nonce argument to decrypt the AES256 input file")
			//fmt.Println(fmt.Sprintf("[!]A %d byte nonce was provided but %d byte nonce was expected", len(inputNonce)/2, gcm.NonceSize()))
		}
		decryptNonce, errDecryptNonce := hex.DecodeString(inputNonce)
		if errDecryptNonce != nil {
			//fmt.Println("[!]%s", errDecryptNonce.Error())
		}
		//fmt.Println(fmt.Sprintf("[-]AES256 nonce (hex): %x", decryptNonce))

		var errDecryptedBytes error
		decryptedBytes, errDecryptedBytes = gcm.Open(nil, decryptNonce, shellcode, nil)
		if errDecryptedBytes != nil {
			//fmt.Println("[!]%s", errDecryptedBytes.Error())
		}
	}
	return decryptedBytes
}
