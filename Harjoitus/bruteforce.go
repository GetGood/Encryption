package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
  "time"
)

func main() {
	// read original and encrypted file paths
	cipherpath := os.Args[1]
	originalpath := os.Args[2]

	// read the files into byte slices
	cipherslice, err := ioutil.ReadFile(cipherpath)
	check(err)

	original, err := ioutil.ReadFile(originalpath)
	check(err)

	// check for and remove line feed character LF
	if cipherslice[len(cipherslice)-1] == 10 {
		cipherslice = cipherslice[:len(cipherslice)-1]
	}

	if original[len(original)-1] == 10 {
		original = original[:len(original)-1]
	}

	cipherslice = cipherslice[32:]

	ciphertext := hex.EncodeToString(cipherslice)

	// feed the cipher slice to function as string.
	// it will be decoded later
	bruteforce(original, ciphertext)
}

// error checking function
func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func bruteforce(original []byte, cipher string) {
	// bruteforcing all possible keys
	// very simplistic progress bar
  start := time.Now()
	for i := 0; i <= 999999999; i++ {
    if i%10000 == 0 && i != 0 {
      t := time.Now()
      elapsed := t.Sub(start)
      fmt.Println("10000 rounds in", elapsed)
      start = time.Now()
    }

		key := generateKey(i)
		testcipher, err := hex.DecodeString(cipher)
		check(err)

		plain := decrypt(key, testcipher)

		if compareSlices(original, plain) != false {
			fmt.Println()
			fmt.Println("key found! key:", hex.EncodeToString(key))
			fmt.Println(key)
			fmt.Print("plaintext: ")
			fmt.Printf("%s\n", plain)
			err := ioutil.WriteFile("newkey.lit", []byte(hex.EncodeToString(key)), 0644)
			if err != nil {
				panic(err)
			}
			break
		}
	}
}

// decrypt function
func decrypt(key []byte, text []byte) []byte {
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

func generateKey(seed int) []byte {
	rand.Seed(int64(seed))
	key := make([]byte, 16)
	rand.Read(key)
	return key
}

func compareSlices(original []byte, test []byte) bool {
	// if slices are different lengths no more checking
	// is required
	if len(original) != len(test) {
		return false
	}

	// loop through every byte of the slices
	for i, char := range original {
		if char != test[i] {
			return false
		}
	}
	return true
}
