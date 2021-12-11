// Author: 99% of code from Ne0nd0g, modified to fit my needs
// https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/ShellcodeUtils/main.go

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	// X Packages
	"golang.org/x/crypto/argon2"

	// 3rd Party
	"github.com/fatih/color"
)

func main() {
	verbose := flag.Bool("v", false, "Enable verbose output")
	encryptionType := flag.String("type", "", "The type of encryption to use [xor, aes256, rc4, null]")
	key := flag.String("key", "", "Encryption key")
	b64 := flag.Bool("base64", false, "Base64 encode the output. Can be used with or without encryption")
	input := flag.String("i", "", "Input file path of binary file")
	output := flag.String("o", "", "Output file path")
	mode := flag.String("mode", "encrypt", "Mode of operation to perform on the input file [encrypt,decrypt]")
	salt := flag.String("salt", "", "Salt, in hex, used to generate an AES256 32-byte key through Argon2. Only used during decryption")
	inputNonce := flag.String("nonce", "", "Nonce, in hex, used to decrypt an AES256 input file. Only used during decryption")
	hex2bin := flag.Bool("hex2bin", false, "Convert a hex encoded string to a binary file")
	hexOut := flag.Bool("hexout", false, "Save output in hex for copy pasting")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	// Check to make sure the input file exists
	_, errInputFile := os.Stat(*input)

	if os.IsNotExist(errInputFile) {
		color.Red(fmt.Sprintf("[!]The file does not exist: %s", *input))
		os.Exit(1)
	}

	shellcode, errShellcode := ioutil.ReadFile(*input)

	if errShellcode != nil {
		color.Red(fmt.Sprintf("[!]%s", errShellcode.Error()))
		os.Exit(1)
	}

	// Check to make sure an output file was provided
	if *output == "" {
		color.Red("[!]The -o output argument is required")
		os.Exit(1)
	}

	// Check to make sure the output directory exists
	dir, outFile := filepath.Split(*output)
	if *verbose {
		color.Yellow(fmt.Sprintf("[-]Output directory: %s", dir))
		color.Yellow(fmt.Sprintf("[-]Output file name: %s", outFile))
	}

	outDir, errOutDir := os.Stat(dir)
	if errOutDir != nil {
		color.Red(fmt.Sprintf("[!]%s", errOutDir.Error()))
		os.Exit(1)
	}

	if !outDir.IsDir() {
		color.Red(fmt.Sprintf("[!]The output directory does not exist: %s", dir))
	}

	if *verbose {
		color.Yellow(fmt.Sprintf("[-]File contents (hex): %x", shellcode))
	}

	if *hex2bin {
		re := regexp.MustCompile(`(0x|,| |\r|\n)`)
		sc := re.ReplaceAll(shellcode, []byte(""))
		//sc := re.ReplaceAll([]byte("48656c6c6f20476f7068657221"), []byte(""))

		outputBytes := make([]byte, hex.DecodedLen(len(sc)))
		_, err := hex.Decode(outputBytes, sc)

		if err != nil {
			color.Red(fmt.Sprintf("[!]%s", err.Error()))
			os.Exit(1)
		}

		writeFile(*output, outputBytes, *encryptionType, "read", *hexOut)
		os.Exit(0) //we're just converting, bail
	}

	if strings.ToUpper(*mode) != "ENCRYPT" && strings.ToUpper(*mode) != "DECRYPT" {
		color.Red("[!]Invalid mode provided. Must be either encrypt or decrypt")
		os.Exit(1)
	}

	// Make sure a key was provided
	if *encryptionType != "" {
		if *key == "" {
			color.Yellow("[+] No key provided, generating one...")
			rnd := make([]byte, 16)
			dst := make([]byte, 32)
			rand.Read(rnd)
			hex.Encode(dst, rnd)
			*key = string(dst)
		}
	}

	var outputBytes []byte

	switch strings.ToUpper(*mode) {
	case "ENCRYPT":
		var encryptedBytes []byte
		switch strings.ToUpper(*encryptionType) {
		case "XOR":
			// https://kylewbanks.com/blog/xor-encryption-using-go
			if *verbose {
				color.Yellow(fmt.Sprintf("[-]XOR encrypting input file with key: %s", *key))
			}
			encryptedBytes = make([]byte, len(shellcode))
			tempKey := *key
			for k, v := range shellcode {
				encryptedBytes[k] = v ^ tempKey[k%len(tempKey)]
			}
		case "AES256":
			// https://github.com/gtank/cryptopasta/blob/master/encrypt.go
			if *verbose {
				color.Yellow("[-]AES256 encrypting input file")
			}

			// Generate a salt that is used to generate a 32 byte key with Argon2
			salt := make([]byte, 32)
			_, errReadFull := io.ReadFull(rand.Reader, salt)
			if errReadFull != nil {
				color.Red(fmt.Sprintf("[!]%s", errReadFull.Error()))
				os.Exit(1)
			}
			color.Green(fmt.Sprintf("salt := \"%x\" // Argon (hex)", salt))

			// Generate Argon2 ID key from input password using a randomly generated salt
			aesKey := argon2.IDKey([]byte(*key), salt, 1, 64*1024, 4, 32)
			// I leave it up to the operator to use the password + salt for decryption or just the Argon2 key
			color.Green(fmt.Sprintf("key := \"%s\" // AES256 key (32-bytes) derived from password (hex): %x", *key, aesKey))

			// Generate AES Cipher Block
			cipherBlock, err := aes.NewCipher(aesKey)
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", err.Error()))
			}
			gcm, errGcm := cipher.NewGCM(cipherBlock)
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", errGcm.Error()))
				os.Exit(1)
			}

			// Generate a nonce (or IV) for use with the AES256 function
			nonce := make([]byte, gcm.NonceSize())
			_, errNonce := io.ReadFull(rand.Reader, nonce)
			if errNonce != nil {
				color.Red(fmt.Sprintf("[!]%s", errNonce.Error()))
				os.Exit(1)
			}

			color.Green(fmt.Sprintf("inputNonce := \"%x\" // AES256 nonce (hex)", nonce))

			encryptedBytes = gcm.Seal(nil, nonce, shellcode, nil)
		case "RC4":
			if *verbose {
				color.Yellow("[-]RC4 encrypting input file")
			}
			cipher, err := rc4.NewCipher([]byte(*key))
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", err.Error()))
				os.Exit(1)
			}
			encryptedBytes = make([]byte, len(shellcode))
			cipher.XORKeyStream(encryptedBytes, shellcode)
		case "":
			if *verbose {
				color.Yellow("[-]No encryption type provided, continuing on...")
			}
			encryptedBytes = append(encryptedBytes, shellcode...)
		default:
			color.Red(fmt.Sprintf("[!]Invalid method type: %s", *encryptionType))
			os.Exit(1)
		}

		if len(encryptedBytes) <= 0 {
			color.Red("[!]Encrypted byte slice length is equal to or less than 0")
			os.Exit(1)
		}
		if *b64 {
			outputBytes = make([]byte, base64.StdEncoding.EncodedLen(len(encryptedBytes)))
			base64.StdEncoding.Encode(outputBytes, encryptedBytes)
		} else {
			outputBytes = append(outputBytes, encryptedBytes...)
		}
	case "DECRYPT":
		var decryptedBytes []byte
		switch strings.ToUpper(*encryptionType) {
		case "AES256":
			// https://github.com/gtank/cryptopasta/blob/master/encrypt.go
			if *verbose {
				color.Yellow("[-]AES256 decrypting input file")
			}
			// I leave it up to the operator to use the password + salt for decryption or just the Argon2 key
			if *salt == "" {
				color.Red("[!]A 32-byte salt in hex format must be provided with the -salt argument to decrypt AES256 input file")
				os.Exit(1)
			}
			if len(*salt) != 64 {
				color.Red("[!]A 32-byte salt in hex format must be provided with the -salt argument to decrypt AES256 input file")
				color.Red(fmt.Sprintf("[!]A %d byte salt was provided", len(*salt)/2))
				os.Exit(1)
			}

			saltDecoded, errSaltDecoded := hex.DecodeString(*salt)
			if errShellcode != nil {
				color.Red(fmt.Sprintf("[!]%s", errSaltDecoded.Error()))
				os.Exit(1)
			}
			if *verbose {
				color.Yellow("[-]Argon2 salt (hex): %x", saltDecoded)
			}

			aesKey := argon2.IDKey([]byte(*key), saltDecoded, 1, 64*1024, 4, 32)
			if *verbose {
				color.Yellow("[-]AES256 key (hex): %x", aesKey)
			}

			cipherBlock, err := aes.NewCipher(aesKey)
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", err.Error()))
			}

			gcm, errGcm := cipher.NewGCM(cipherBlock)
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", errGcm.Error()))
				os.Exit(1)
			}

			if len(shellcode) < gcm.NonceSize() {
				color.Red("[!]Malformed ciphertext is larger than nonce")
				os.Exit(1)
			}

			if len(*inputNonce) != gcm.NonceSize()*2 {
				color.Red("[!]A nonce, in hex, must be provided with the -nonce argument to decrypt the AES256 input file")
				color.Red(fmt.Sprintf("[!]A %d byte nonce was provided but %d byte nonce was expected", len(*inputNonce)/2, gcm.NonceSize()))
				os.Exit(1)
			}
			decryptNonce, errDecryptNonce := hex.DecodeString(*inputNonce)
			if errDecryptNonce != nil {
				color.Red("[!]%s", errDecryptNonce.Error())
				os.Exit(1)
			}
			if *verbose {
				color.Yellow(fmt.Sprintf("[-]AES256 nonce (hex): %x", decryptNonce))
			}

			var errDecryptedBytes error
			decryptedBytes, errDecryptedBytes = gcm.Open(nil, decryptNonce, shellcode, nil)
			if errDecryptedBytes != nil {
				color.Red("[!]%s", errDecryptedBytes.Error())
				os.Exit(1)
			}
		case "XOR":
			// https://kylewbanks.com/blog/xor-encryption-using-go
			if *verbose {
				color.Yellow(fmt.Sprintf("[-]XOR decrypting input file with key: %s", *key))
			}
			decryptedBytes = make([]byte, len(shellcode))
			tempKey := *key
			for k, v := range shellcode {
				decryptedBytes[k] = v ^ tempKey[k%len(tempKey)]
			}
		case "RC4":
			if *verbose {
				color.Yellow("[-]RC4 decrypting input file")
			}
			cipher, err := rc4.NewCipher([]byte(*key))
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", err.Error()))
				os.Exit(1)
			}
			decryptedBytes = make([]byte, len(shellcode))
			cipher.XORKeyStream(decryptedBytes, shellcode)
		default:
			color.Red("[!]Invalid method")
			os.Exit(1)
		}
		if len(decryptedBytes) <= 0 {
			color.Red("[!]Decrypted byte slice length is equal to or less than 0")
			os.Exit(1)
		}
		if *b64 {
			outputBytes = make([]byte, base64.StdEncoding.EncodedLen(len(decryptedBytes)))
			base64.StdEncoding.Encode(outputBytes, decryptedBytes)
		} else {
			outputBytes = append(outputBytes, decryptedBytes...)
		}
	}

	if *verbose {
		if *b64 {
			color.Green("[+]Output (string):\r\n")
			fmt.Printf(fmt.Sprintf("%s\n", outputBytes))
		} else {
			color.Green("[+]Output (hex):\r\n")
			fmt.Printf(fmt.Sprintf("%x\n", outputBytes))
		}
	}

	writeFile(*output, outputBytes, *encryptionType, *mode, *hexOut)
}

func writeFile(output string, outputBytes []byte, encryptionType string, mode string, hexOut bool) {
	if hexOut {
		hexstring := make([]byte, len(outputBytes)*2)
		hex.Encode(hexstring, outputBytes)
		err := ioutil.WriteFile(output, hexstring, 0660)
		if err != nil {
			color.Red(fmt.Sprintf("[!]%s", err.Error()))
			os.Exit(1)
		}
	} else {
		err := ioutil.WriteFile(output, outputBytes, 0660)
		if err != nil {
			color.Red(fmt.Sprintf("[!]%s", err.Error()))
			os.Exit(1)
		}
	}

	color.Green(fmt.Sprintf("[+]%s %s input and wrote %d bytes to: %s", encryptionType, mode, len(outputBytes), output))

}

/*
func ConvertBytesToUUID(shellcode []byte) {
		// Pad shellcode to 16 bytes, the size of a UUID
		if 16-len(shellcode)%16 < 16 {
			pad := bytes.Repeat([]byte{byte(0x90)}, 16-len(shellcode)%16)
			shellcode = append(shellcode, pad...)
		}

		var uuids []string
		for i := 0; i < len(shellcode); i += 16 {
			u, err := uuid.FromBytes(shellcode[i:i+16])
			if err != nil {
				fmt.Errorf("there was an error converting bytes into a UUID:\n%s", err)
			}
			uuids = append(uuids, u.String())
		}

		for _, v := range uuids {
			fmt.Printf("%s\n", v)
		}
}
*/
