package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	cryptosecure "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"
)

func main() {

	decryptPtr := flag.String("d", "", "option to decrypt")
	encryptPtr := flag.String("e", "", "option to encrypt")
	useKeyPtr := flag.String("k", "", "option to use key file")
	flag.Parse()

	if *encryptPtr != "" {
		originalpath := *encryptPtr
		originaltext, err := ioutil.ReadFile(originalpath)
		check(err)

		// check for and remove line feed character LF
		if originaltext[len(originaltext)-1] == 10 {
			originaltext = originaltext[:len(originaltext)-1]
		}
		if *useKeyPtr != "" {
			keypath := *useKeyPtr
			keyfile, err := ioutil.ReadFile(keypath)
			check(err)

			key, err := hex.DecodeString(string(keyfile))
			check(err)

			ciphertext := encrypt(key, originaltext)
			completeMac := createHmac(ciphertext, key)

			completeText := append(completeMac, ciphertext...)

			err = ioutil.WriteFile("./"+originalpath+".lit", completeText, 0644)
			check(err)

			fmt.Println("Created encrypted file using key")

		} else {
			key := generateKey()
			ciphertext := encrypt(key, originaltext)

			completeMac := createHmac(ciphertext, key)

			completeText := append(completeMac, ciphertext...)

			err = ioutil.WriteFile("./"+originalpath+".lit", completeText, 0644)
			check(err)

			err = ioutil.WriteFile("key.lit", []byte(hex.EncodeToString(key)), 0644)
			check(err)

			fmt.Println("Created encrypted file and a new key")
		}
	} else if *decryptPtr != "" && *useKeyPtr != "" {
		originalpath := *decryptPtr
		filename := stripExtension(originalpath)
		keypath := *useKeyPtr
		originaltext, err := ioutil.ReadFile(originalpath)
		check(err)

		// check for and remove line feed character LF
		if originaltext[len(originaltext)-1] == 10 {
			originaltext = originaltext[:len(originaltext)-1]
		}

		keyfile, err := ioutil.ReadFile(keypath)
		check(err)

		key, err := hex.DecodeString(string(keyfile))
		check(err)

		hmacHeader, textBytes := originaltext[:32], originaltext[32:]

		if checkMac(textBytes, hmacHeader, key) != true {
			fmt.Println("Integrity has been compromised!")
			os.Exit(3)
		} else {
			fmt.Println("Message intact, proceeding")
		}

		plaintext := decrypt(key, textBytes)
		err = ioutil.WriteFile("./"+filename, plaintext, 0644)
		if err != nil {
			panic(err)
		}
		fmt.Println("File decrypted")
	} else {
		fmt.Println("Invalid command line option, use")
		fmt.Println("-d for decrypt, -e for encrypt, specify keyfile with -k")
	}
}

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func stripExtension(s string) string {
	n := strings.LastIndexByte(s, '.')
	if n > 0 {
		return s[:n]
	}
	return s
}

func decrypt(key []byte, text []byte) []byte {
	fmt.Println("Decrypting data...")
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(text) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(text, text)
	// Output: some plaintext
	return text
}

func encrypt(key []byte, text []byte) []byte {
	fmt.Println("Encrypting data...")
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(cryptosecure.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], text)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return ciphertext
}

func createHmac(ciphertext []byte, key []byte) []byte {
	fmt.Println("Creating HMAC...")
	hashSlice := append(ciphertext, key...)

	macKeyHash := sha256.New()
	macKeyHash.Write(key)
	macKey := macKeyHash.Sum(nil)

	mac := hmac.New(sha256.New, macKey)
	mac.Write(hashSlice)
	completeMac := mac.Sum(nil)
	return completeMac
}

func checkMac(originaltext []byte, hmacHeader []byte, key []byte) bool {
	fmt.Println("Checking data integrity...")
	hashSlice := append(originaltext, key...)

	macKeyHash := sha256.New()
	macKeyHash.Write(key)
	macKey := macKeyHash.Sum(nil)

	mac := hmac.New(sha256.New, macKey)
	mac.Write(hashSlice)
	expectedMac := mac.Sum(nil)
	return hmac.Equal(hmacHeader, expectedMac)
}

func generateKey() []byte {
	fmt.Println("Generating key...")
	now := time.Now()
	seed := (now.Nanosecond())
	rand.Seed(int64(seed))
	key := make([]byte, 16)
	rand.Read(key)
	return key
}
