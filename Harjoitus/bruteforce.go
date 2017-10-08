package main

import (
  "fmt"
  "math/rand"
  "strconv"
  "encoding/hex"
  "crypto/aes"
  "crypto/cipher"
  "log"
  "os"
)

func main() {
  originaltext := []byte("hello world! I like to get encrypted sometimes")
  cipherstring := os.Args[1]

  for i := 1; i <= 999999999; i++ {
    if i%10000 == 0 {
      fmt.Println(i, "rounds done")
    }
    ciphertext, err := hex.DecodeString(cipherstring)
    if err != nil {
      log.Fatal(err)
    }

    key := generateKey(i)

    plaintext := decrypt(key, ciphertext)

    if compareSlices(originaltext, plaintext) != false {
      fmt.Println("key found! key:", hex.EncodeToString(key))
      fmt.Println(key)
      fmt.Print("plaintext: ")
      fmt.Printf("%s\n", plaintext)
      break
    }
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


func generateKey(seed int) ([]byte) {
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

func compareSlices(original []byte, test []byte) (bool) {
  if len(original) != len(test) {
    return false
  }

  for i, char := range original {
    if char != test[i] {
      return false
    }
  }

  return true
}
