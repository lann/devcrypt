# **This isn't ready for anyone to use for anything! Don't do it!**

# DevCrypt - encrypt your development secrets

## Quickstart

```
$ git clone https://github.com/lann/devcrypt
$ cd devcrypt
$ go build

$ ./devcrypt keygen
Generating key with label "lann@computer"...
Wrote private key to "/home/lann/.config/devcrypt/devcrypt_key"
Wrote public key to "/home/lann/.config/devcrypt/devcrypt_key.pub"
Public key:
devcrypt-key cpCWOPP0/afWR3YkfrxZ6KptOO9pAZflm3LF6ChoTXU= lann@computer

$ echo "SECRET_KEY=topSecret" > .env
$ ./devcrypt encrypt .env
Encrypted to ".env.devcrypt"

$ ./devcrypt keygen -k bobs_key -l bob@boblandia
...
Wrote public key to "bobs_key.pub"
...
$ ./devcrypt add .env.devcrypt bobs_key.pub
Adding public key labeled "bob@boblandia"
Updated ".env.devcrypt"

$ ./devcrypt decrypt .env.devcrypt
Decrypted to ".env"
```

## Cryptography

DevCrypt uses cryptographic elements from NaCl as implemented in
[golang.org/x/crypto/nacl](https://pkg.go.dev/golang.org/x/crypto/nacl).

Files are encryped with [secretbox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox) using a random "file key". That key is then encrypted into one or more "[sealed boxes](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes)", which allow encryption with a public key and decryption with the matching private key. The sealed boxes and matching public keys are stored along with the encrypted file in a single text file.

Users with private keys that match one of the "sealed boxes" can decrypt the file by looking up the sealed box based on their public key, decrypting the file key using their private key, then decrypting the file contents with the file key. They can also add new public keys to the encrypted file by decrypting the file key and then reencrypting it into a new sealed box.
