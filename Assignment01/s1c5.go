package main

import (
  "fmt"
  "os"
  "io/ioutil"
  "encoding/hex"
)

// error checking method for ioutil operations
func check(e error) {
  if e != nil {
    panic(e)
  }
}

func xor(data []byte, key []byte) []byte {
  length := len(data)
  cipher := make([]byte, length)
  counter := 0
  for i := 0; i < length; i++ {
    if(counter == 3) {
      counter = 0
    }
    cipher[i] = (data[i]^key[counter])
    counter++
  }
  return cipher
}


func main() {
  // read file path as command line argument
  path := os.Args[1]
  // define key to a slice of bytes
  key := []byte("ICE")
  // read the file defined in the command line arguments
  data, err := ioutil.ReadFile(path)
  check(err)
  // remove line feed character LF
  if (data[len(data)-1] == 10) {
    data = data[:len(data)-1]
  }

  cipher := xor(data, key)
  // encode the xored bytes to hex for prettier
  // output
  cipherString := hex.EncodeToString(cipher)
  fmt.Println("Encrypted data in a hex string:")
  fmt.Println(cipherString)
}
