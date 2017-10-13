package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"strconv"
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
			err = ioutil.WriteFile("./"+originalpath+".lit", ciphertext, 0644)
			check(err)
		} else {
			key := generateKey()
			ciphertext := encrypt(key, originaltext)
			err = ioutil.WriteFile("./"+originalpath+".lit", ciphertext, 0644)
			check(err)
			err = ioutil.WriteFile("key.lit", []byte(hex.EncodeToString(key)), 0644)
			check(err)
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

		plaintext := decrypt(key, originaltext)
		err = ioutil.WriteFile("./"+filename, plaintext, 0644)
		if err != nil {
			panic(err)
		}
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
	now := time.Now()
	seed := (now.Nanosecond())
	fmt.Println("seed:", seed)
	rand.Seed(int64(seed))

	ivbyte := make([]byte, 1)
	ivchar := ""
	ivnum := 0
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]

	for i := 0; i < len(iv); {
		ivchar = (strconv.Itoa(rand.Int()))[0:3]
		ivnum, _ = strconv.Atoi(ivchar)
		if ivnum > 0 && ivnum < 127 {
			ivchar = string(ivnum)
			ivbyte = []byte(ivchar)
			iv[i] = ivbyte[0]
			i++
		} else {
			continue
		}
	}
	fmt.Println(iv)

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], text)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return ciphertext
}

func generateKey() []byte {
	now := time.Now()
	seed := (now.Nanosecond())
	fmt.Println("seed:", seed)
	rand.Seed(int64(seed))
	key := make([]byte, 16)
	keychar := ""
	keybyte := make([]byte, 1)
	keynum := 0

	for i := 0; i < 16; {
		keychar = (strconv.Itoa(rand.Int()))[0:3]
		keynum, _ = strconv.Atoi(keychar)
		if keynum > 0 && keynum < 128 {
			//fmt.Println(keynum)
			keychar = string(keynum)
			//fmt.Println(keychar)
			keybyte = []byte(keychar)
			key[i] = keybyte[0]
			i++
		} else {
			continue
		}
	}
	return key
}
