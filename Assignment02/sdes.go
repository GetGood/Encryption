package main

import (
  "fmt"
  "bufio"
  "os"
  "strconv"
  "flag"
)


func generateKeys() ([]byte, []byte) {
  // static values for key generation
  P10 := []int{2, 4, 1, 6, 3, 9, 0, 8, 7, 5}
  P8 := []int{5, 2, 6, 3, 7, 4, 9, 8}

  // read in the key from stdin
  scanner := bufio.NewScanner(os.Stdin)
  fmt.Println("Enter 10 bit key:")
  scanner.Scan()
  input := scanner.Text()

  // sanitize the input
  for _,c := range input {
    if (string(c) != "0" && string(c) != "1") {
      fmt.Println("Enter only 0s or 1s")
      os.Exit(3)
    }
  }

  if (len(input) != 10) {
    fmt.Println("Key should be exactly 10 bits")
    os.Exit(4)
  }

  // create a new byte array and permutate the
  // key according to P10
  key, Pkey := []byte(input), make([]byte, len(input))
  for i,pos := range P10 {
    Pkey[i] = key[pos]
  }

  // perform a circular left shift separately
  // on the first and last 5 bits of the key
  left, right := Pkey[:5], Pkey[5:]
  leftShift(&left, 1)
  leftShift(&right, 1)
  // put the left and the right part back
  // together
  Pkey = append(left, right...)

  // permutate the key according to P8
  K1 := make([]byte, len(Pkey))
  for i, pos := range P8 {
    K1[i] = Pkey[pos]
  }

  // perform circular left shift by 2
  // positions on the halves created
  // earlier
  leftShift(&left, 2)
  leftShift(&right, 2)
  // put together key number 2
  Pkey = append(left, right...)
  K2 := make([]byte, len(Pkey))
  // permutate key 2 according to P8
  for i, pos := range P8 {
    K2[i] = Pkey[pos]
  }

  return K1, K2
}

func getInput() ([]byte) {
  // value for permutation
  IP := []int{1, 5, 2, 0, 3, 7, 4, 6}

  // read the plaintext from stdin and
  // insert it into a slice of bytes
  // we'll mostly be operating on characters
  // found inside the slice
  scanner := bufio.NewScanner(os.Stdin)
  fmt.Println("Enter 8 bit input:")
  scanner.Scan()
  inputString := scanner.Text()

  // sanitize the input
  for _,c := range inputString {
    if (string(c) != "0" && string(c) != "1") {
      fmt.Println("Enter only 0s or 1s")
      os.Exit(3)
    }
  }

  if (len(inputString) != 8) {
    fmt.Println("Key should be exactly 8 bits")
    os.Exit(4)
  }


  inputSlice := []byte(inputString)
  input := make([]byte, len(inputSlice))

  // permutate the input according to IP
  for i,pos := range IP {
    input[i] = inputSlice[pos]
  }

  return input
}

func F(input[]byte, key[]byte)([]byte) {
  // value for permutation/expansion
  EP := []int{3, 0, 1, 2, 1, 2, 3, 0}

  // cut the input in half and permutate/
  // expand the last 4 bits according to EP
  left, right := input[:4], input[4:]
  EPright := make([]byte, (len(right)*2))
  for i,pos := range EP {
    EPright[i] = right[pos]
  }

  // perform bit-by-bit xor against the
  // supplied key and store the results
  textbit, keybit, xorbit := 0,0,0
  xorbyte := make([]byte, 1)
  for i,_ := range EPright {
    // we omit some error checks here trusting
    // the sanitized input
    textbit,_ = strconv.Atoi(string(EPright[i]))
    keybit,_ = strconv.Atoi(string(key[i]))
    xorbit = keybit ^ textbit
    xorbyte = []byte(strconv.Itoa(xorbit))
    EPright[i] = xorbyte[0]
  }
  // cut the resulting 8 bits in half
  first, last := EPright[:4], EPright[4:]
  // feed the values into the SBox and store
  // the results into a slice of bytes
  xorkey := Sbox(first, last)

  // perform a bit-by-bit xor to the 
  // left side 4 bits against the value
  // received from the SBox
  for i,_ := range xorkey {
    textbit,_ = strconv.Atoi(string(left[i]))
    keybit, _ = strconv.Atoi(string(xorkey[i]))
    xorbit = keybit ^ textbit
    xorbyte = []byte(strconv.Itoa(xorbit))
    left[i] = xorbyte[0]
  }

  // put the results back together
  output := append(left, right...)

  return output
}

func Sbox(first []byte, last []byte) ([]byte){
  // define the Sboxes
  S0 := [][]int{
    {1,0,3,2},
    {3,2,1,0},
    {0,2,1,3},
    {3,1,3,2}}

  S1 := [][]int {
    {0,1,2,3},
    {2,0,1,3},
    {3,0,1,0},
    {2,1,0,3}}

  // a value for permutation
  P4 := []int{1,3,2,0}

  // store the values inside the first 4 bits
  // inside variables
  a, b := first[0], first[3]
  c, d := first[1], first[2]

  // interpret the bit value that results from adding
  // two variables together into an int. so "0" + "1"
  // becomes int 1 and "1" + "1" becomes int 3
  row,_ := strconv.ParseInt((string(a)+string(b)), 2, 64)
  column,_ := strconv.ParseInt((string(c)+string(d)), 2, 64)
  s0int := S0[row][column]
  // interpret the value received from the sBox into
  // a string representing a binary number
  s0value := strconv.FormatInt(int64(s0int), 2)

  // if the value is 0 or 1 pad the result
  // with one zero to 00 or 01
  if (len(s0value)== 1) {
    s0value = "0" + s0value
  }

  // perform similar changes to leftmost 4 bits
  a, b = last[0], last[3]
  c, d = last[1], last[2]
  // omitting error checks
  row,_ = strconv.ParseInt((string(a)+string(b)), 2, 64)
  column,_ = strconv.ParseInt((string(c)+string(d)), 2, 64)
  s1int := S1[row][column]
  s1value := strconv.FormatInt(int64(s1int), 2)
  if (len(s1value)== 1) {
    s1value = "0" + s1value
  }

  // turn the string representing a binary value
  // back into a slice of bytes
  bitstring := s0value + s1value
  bitSlice := []byte(bitstring)

  // permutate the slice according to P4
  Pvalue := make([]byte, len(bitSlice))
  for i,pos := range P4 {
    Pvalue[i] = bitSlice[pos]
  }
  return Pvalue
}

// receive a pointer to a slice, perform circular
// left shift as many positions as int i dictates
func leftShift(slice *[]byte, i int) {
  a, b := (*slice)[:i], (*slice)[i:]
  *slice = append(b, a...)
}

// receive a pointer to a slice, swap left and
// right 4 bits
func swap(slice *[]byte) {
  left, right := (*slice)[:4], (*slice)[4:]
  *slice = append(right, left...)
}

func encrypt() ([]byte) {
  reverse_IP := []int{3, 0, 2, 4, 6, 1, 7, 5}

  K1,K2 := generateKeys()
  input := getInput()
  fK1 := F(input, K1)
  swap(&fK1)
  fK2 := F(fK1, K2)

  ciphertext := make([]byte, len(fK2))
  // reverse the IP permutation performed
  // in the getInput() -function
  for i,pos := range reverse_IP {
    ciphertext[i] = fK2[pos]
  }

  return ciphertext
}

func decrypt() ([]byte) {
  reverse_IP := []int{3, 0, 2, 4, 6, 1, 7, 5}

  K1,K2 := generateKeys()
  input := getInput()
  fK1 := F(input, K2)
  swap(&fK1)
  fK2 := F(fK1, K1)

  plaintext := make([]byte, len(fK2))
  // reverse the IP permutation
  for i,pos := range reverse_IP {
    plaintext[i] = fK2[pos]
  }

  return plaintext
}

func main() {
  decryptPtr := flag.Bool("d", false, "option to decrypt")
  encryptPtr := flag.Bool("e", false, "option to encrypt")
  flag.Parse()
  if (*encryptPtr == true) {
    fmt.Println("ciphertext:", string(encrypt()))
  } else if (*decryptPtr == true) {
    fmt.Println("plaintext:", string(decrypt()))
  } else {
    fmt.Println("Invalid command line option, use")
    fmt.Println("-d for decrypt, -e for encrypt")
  }
}
