package main

import (
  "fmt"
  "bufio"
  "os"
  "encoding/hex"
  "log"
)

const staticHex = "686974207468652062756c6c277320657965"

func main() {
  // read the hex string from stdin
  scanner := bufio.NewScanner(os.Stdin)
  fmt.Println("Enter the hex string for xor operation")
  scanner.Scan()
  plain := scanner.Text()

  // decode the hex string into a byte array
  decode, err := hex.DecodeString(plain)
  if err != nil {
    log.Fatal(err)
  }

  // decode the key into a byte array
  key, err := hex.DecodeString(staticHex)
  if err != nil {
    log.Fatal(err)
  }

  // xor the two byte arrays into a new byte array
  length := len(key)
  cipher := make([]byte, length)
  for i := 0; i < length; i++ {
    cipher[i] = decode[i] ^ key[i]
  }

  // encode the resulting byte array into a hex string
  cipherString := hex.EncodeToString(cipher)
  fmt.Println("Encoded string:", cipherString)
}
