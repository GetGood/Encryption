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
	"os"
	"strconv"
	"time"
	"strings"
)

func main() {

	decryptPtr := flag.Bool("d", false, "option to decrypt")
	encryptPtr := flag.Bool("e", false, "option to encrypt")
	useKeyPtr := flag.Bool("k", false, "option to use key file")
	flag.Parse()
	if *encryptPtr == true {
		originalpath := os.Args[2]
		originaltext, err := ioutil.ReadFile(originalpath)
		check(err)
		// check for and remove line feed character LF
		if originaltext[len(originaltext)-1] == 10 {
		originaltext = originaltext[:len(originaltext)-1]
    }
		if *useKeyPtr == true{
			keypath := os.Args[4]
			keyfile, err := ioutil.ReadFile(keypath)
			key, err := hex.DecodeString(string(keyfile))
			check(err)
			ciphertext := encrypt(key, originaltext)
			err = ioutil.WriteFile("./"+originalpath + ".lit", ciphertext, 0644)
		}else{
		
		key := generateKey()
		err = ioutil.WriteFile("key.lit", []byte(hex.EncodeToString(key)), 0644)
		if err != nil {
			panic(err)
		}
		}
		if err != nil {
			panic(err)
		}
	} else if *decryptPtr == true {
		originalpath := os.Args[2]
		originaltext, err := ioutil.ReadFile(originalpath)
		check(err)
		// check for and remove line feed character LF
		if originaltext[len(originaltext)-1] == 10 {
		originaltext = originaltext[:len(originaltext)-1]
    }
		filename := stripExtension(os.Args[2])
		if *useKeyPtr == true{
			keypath := os.Args[4]
			keyfile, err := ioutil.ReadFile(keypath)
			key, err := hex.DecodeString(string(keyfile))
			check(err)
			plaintext := decrypt(key, originaltext)
			err = ioutil.WriteFile("./"+filename, plaintext, 0644)
			if err != nil {
			panic(err)
		}
		}else{
			key := generateKey()
			plaintext := decrypt(key, originaltext)
			err = ioutil.WriteFile("./"+filename, plaintext, 0644)
			if err != nil {
			panic(err)
		}
		}

		
	} else {
		fmt.Println("Invalid command line option, use")
		fmt.Println("-d for decrypt, -e for encrypt")
	}

	//  fmt.Println("key:", hex.EncodeToString(key))
	//fmt.Println(key)

	// fmt.Println("ciphertext:", hex.EncodeToString(ciphertext))
	//fmt.Println("yoyoyo:", ciphertext)

	// fmt.Print("plaintext: ")
	// fmt.Printf("%s\n", plaintext)

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
		if ivnum > 32 && ivnum < 127 {
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
	rand.Seed(int64(2000))
	key := make([]byte, 16)
	keychar := ""
	keybyte := make([]byte, 1)
	keynum := 0

	for i := 0; i < 16; {
		keychar = (strconv.Itoa(rand.Int()))[0:3]
		keynum, _ = strconv.Atoi(keychar)
		if keynum > 32 && keynum < 127 {
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
