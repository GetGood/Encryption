package main

import (
  "fmt"
  "math/rand"
  "time"
  "strconv"
  "crypto/aes"
  "crypto/cipher"
 // "encoding/hex"
  "io/ioutil"
  "os"
  "log"
  "flag"
)

func main() {


 
	key := generateKey()
	decryptPtr := flag.Bool("d", false, "option to decrypt")
	encryptPtr := flag.Bool("e", false, "option to encrypt")
	flag.Parse()
	if (*encryptPtr == true) {
		originalpath := os.Args[2]
		originaltext, err := ioutil.ReadFile(originalpath)
		check(err)
		ciphertext := encrypt(key, originaltext)
		err = ioutil.WriteFile("./results.txt", ciphertext, 0644)
		if err != nil {
		panic(err)
	}
  } else if (*decryptPtr == true) {
		originalpath := os.Args[2]
		 originaltext, err := ioutil.ReadFile(originalpath)
		 check(err)
	 
		plaintext := decrypt(key, originaltext)
		err = ioutil.WriteFile("./plainnsimple.txt", plaintext, 0644)
			if err != nil {
			panic(err)
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

func decrypt(key []byte, text []byte) ([]byte){
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

func encrypt(key []byte, text []byte) ([]byte) {
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
    ivnum,_ = strconv.Atoi(ivchar)
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


func generateKey() ([]byte) {
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
    keynum,_ = strconv.Atoi(keychar)
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