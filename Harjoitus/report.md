# Encryption Techniques
## Litaecrypt
Matti Ruusupiha  
Mikko Seppänen

## 1	Litaecrypt program documentation
###### 1.1	Authors and version
Matti Ruusupiha & Mikko Seppänen
Version 1.0
###### 1.2	Introduction
In this assignment we decided to make an encryption software with a known vulnerability, explain why it’s vulnerable and how to make it secure. For the programming we used the Go programming language. The program was named Litaecrypt. Litaecrypt is a command line tool for encrypting and decrypting files. It uses 128-bit AES for encryption. Originals of the encrypted files are not deleted. The encrypted files use the .lit -extension. The vulnerability comes from using a cryptographically insecure random function for generating the key, more on the random functions later.
###### 1.3	Installation
Litaecrypt is a standalone program that doesn’t require additional files.
There are binaries for 64 and 32-bit Windows or Linux operating systems.
User simply navigates to the folder where the program file is located with a command prompt
or shell such as PowerShell or Bash and runs the program.  
**(LISÄÄ TÄHÄN DOWNLOAD LINKIT BINÄÄREIHIN)**
###### 1.4	Usage
For file encryption, generating a new key file:
```
litaecrypt -e {filename}
```
For file encryption, using an existing key file:
```
litaecrypt -e {filename} -k {keyfile}
```
For file decryption
```
litaecrypt -d {filename} -k {keyfile}
```
## 2	Architechture of Litaecrypt

###### 2.1 Architecture flowchart
![program architecture](architecture.PNG)

## 3	The vulnerability

###### 3.1 About stateful PRNGs
Pseudorandom number generators are algorithms that generate a sequence of numbers whose properties only mimics the properties of truly random sequences. The reason why the PRNG doesn’t produce truly random number sequence is that it’s completely determined by the initial value, called seed. The seed determines the initial starting state of PRNG, it can be set to any arbitrary number (often current system time by milliseconds is used). It will always produce the same sequence of numbers when the same state is used to initialize. Therefore if the method of producing the key is known, in the case of Litaecrypt the basic rand() function, the key can be obtained by brute forcing the initial seed, if the plaintext and ciphertext are also known.
###### 3.2 Exploiting Litaecrypt
How would one go about exploiting the vulnerability that exist in Litaecrypt then? Earlier we learned, that PRNGs produce always the same number no matter what, if the state of the random number generator stays the same. In Golang, the random number generator is seeded with the integer 1 by default. If math/rand was used as is, it would generate the same key every time. This is not the case with Litaecrypt however, because the imagined developer went through the trouble of seeding rand with a value that changes each time the program is ran. That value is time.Nanosecond, which can be any positive integer between 0 and 999999999. While that is a quite large range of numbers, it is still only 1x10^10 keys compared to AES-128’s 3.4x10^38 keys and is quite bruteforceable.  

We are going to assume the possible attacker has access to the source code of the program. Otherwise the attacker could try to reverse the binaries. After confirming the program uses math/rand seeded with time.Nanosecond, the attacker now needs an encrypted file and corresponding plaintext to perform a known-plaintext attack. In practise the attacker doesn’t actually need to know the full plaintext file. For example, commonly .jpeg files have the bytes 0xFF and 0xD8 at the start of the file, and the bytes 0xFF and 0xD9 at the end of the file. Similar standards exist across other types of files. The attacker needs to get creative and recognize this type of encrypted file that has known properties.  

After encrypted file and the corresponding plaintext has been aquired, the attacker only needs to implement the litaecrypt key generation and decrypt functions, and try to decrypt them with keys generated from random seeds 0-999999999. When the decrypted file matches the plaintext, the key has been found.  

We created a proof-of-concept program in Golang to try the bruteforcing in practise.  

Picture: 171KB test_picture.jpg  
Processor: Intel(R) Core(TM) i7-2600K CPU @ 3.40GHz  
Average computing time for 10000 keys: 22,60386205 seconds  
Estimated time to compute all keys: 26 days 3 hours 52 minutes 43 seconds  

###### 3.2 About cryptographically safe PRNGs
###### 3.4 Fixing the vulnerability

Kerrotaan vulnista
Avainsanoja:
Cryptographically secure pseudorandom number generator (CSPRNG)
Pseudorandom number generator (PRNG), deterministic
/dev/urandom (Linux)
CryptGenRandom API (Windows)
rand.Read and crypto rand.Read
