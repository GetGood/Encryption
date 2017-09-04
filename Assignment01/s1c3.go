package main

import (
  "fmt"
  "bufio"
  "os"
  "encoding/hex"
  "log"
  "strings"
)

const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func calculateScore(plainText[]byte) float64 {
  // a map for scoring the resulting string based on character
  // frequency in the english language
  score := map[string]float64{"e": 12.702, "t": 9.056, "a": 8.167, "o": 7.507,
  "i": 6.966, "n": 6.749, "s": 6.327, "h": 6.094, "r": 5.987, "d": 4.253,
  "l": 4.025, "c": 2.782, "u":2.785, "m": 2.406, "w": 2.360, "f": 2.228,
  "g": 2.015, "y": 1.974, "p": 1.929, "b": 1.492, "v": 0.978, "k": 0.772,
  "j": 0.153, "x": 0.150, "q": 0.095, "z": 0.074, " ": 23.20}
  var finalScore float64

  for _,c := range plainText {
    finalScore += score[strings.ToLower(string(c))]
  }

  return finalScore
}

func main() {
  // read the hex string from stdin
  scanner := bufio.NewScanner(os.Stdin)
  fmt.Println("Enter the hex string:")
  scanner.Scan()
  cipher := scanner.Text()

  // decode the hex string into a byte array
  decodeCipher, err := hex.DecodeString(cipher)
  if err != nil {
    log.Fatal(err)
  }

  // create variables for storing and comparing the score
  currentScore, calculatedScore := 0.0, 0.0
  length := len(decodeCipher)
  // make a slice for the loop
  loopString := make([]byte, length)
  finalString := ""
  // copy the contents of the decoded string to loop slice.
  // this needs to be done because the loop slice will be
  // changed during the loop and the original value needs
  // to be restored before the following loop
  copy(loopString, decodeCipher)

  for i := 0; i < len(alphabet); i++ {
    for j := 0; j < length; j++ {
      loopString[j] ^= byte(alphabet[i])
    }
    calculatedScore = calculateScore(loopString)
    if(currentScore < calculatedScore) {
      finalString = ""
      currentScore = calculatedScore
      for _, c := range loopString {
        finalString += string(c)
      }
    }
    copy(loopString, decodeCipher)
  }

  // print the string which is most likely english
  fmt.Println("Plaintext with the highest score:", finalString)
}
