package main

import (
  "fmt"
  "math/rand"
  "time"
  "strconv"
  "crypto/aes"
  "crypto/cipher"
  "encoding/hex"
)

func main() {
  key := generateKey()
  fmt.Println("key:", hex.EncodeToString(key))
  fmt.Println(key)

  originaltext := []byte("hello world! I like to get encrypted sometimes")

  ciphertext := encrypt(key, originaltext)
  fmt.Println("ciphertext:", hex.EncodeToString(ciphertext))

  plaintext := decrypt(key, ciphertext)

  fmt.Print("plaintext: ")
  fmt.Printf("%s\n", plaintext)
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
  block, err := aes.NewCipher(key)
  if err != nil {
    panic(err)
  }

  // The IV needs to be unique, but not secure. Therefore it's common to
  // include it at the beginning of the ciphertext.
  ciphertext := make([]byte, aes.BlockSize+len(text))
  iv := ciphertext[:aes.BlockSize]

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
  rand.Seed(int64(seed))
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
