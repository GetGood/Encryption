# Encryption Techniques
## Litaecrypt
Matti Ruusupiha
Mikko Seppänen

## 1	Litaecrypt program documentation
###### 1.1	Authors and version
Matti Ruusupiha & Mikko Seppänen
Version 1.0
###### 1.2	Introduction
Litaecrypt is a command line tool for encrypting and decrypting files.
It uses 128-bit AES and insecure key generation. Originals of the encrypted files are not deleted.
The encrypted files use the .lit -extension.
###### 1.3	Installation
Litaecrypt is a standalone program that doesn’t require additional files.
There are binaries for 64 and 32-bit Windows or Linux operating systems.
User simply navigates to the folder where the program file is located with a command prompt
or shell such as PowerShell or Bash and runs the program.
###### 1.4	Usage
For file encryption, generating a new key file:
litaecrypt -e {filename}
For file encryption, using an existing key file:
litaecrypt -e {filename} -k {keyfile}
For file decryption
litaecrypt -d {filename} -k {keyfile}
## 2	Architechture of Litaecrypt
 
## 3	The vulnerability
Kerrotaan vulnista
Avainsanoja:
Cryptographically secure pseudorandom number generator (CSPRNG)
Pseudorandom number generator (PRNG), deterministic
/dev/urandom (Linux)
CryptGenRandom API (Windows)
rand.Read and crypto rand.Read
