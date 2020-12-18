# DevCrypt - encrypt your development secrets

The purpose of DevCrypt is to improve otherwise insecure sharing of development
environment (that is, "low value") secrets, such as test database passwords. If
you currently keep these secrets unencrypted in your source code or shared via
e.g. email, DevCrypt may be for you.

**DO NOT USE DEVCRYPT TO PROTECT PRODUCTION OR OTHERWISE HIGH-VALUE SECRETS!**

While DevCrypt is built on secure cryptographic elements, it is immature and
hasn't been thoroughly reviewed by _anyone_, let alone cryptographic experts.

## Quickstart

### Install

DevCrypt is written in [Go](https://golang.org). Currently there are no
binaries available, so you have to compile from source.

To install the devcrypt binary to `$GOBIN` (by default, `~/go/bin/devcrypt`):

```
$ go get -u github.com/lann/devcrypt
$ devcrypt help
```

or, to just compile the binary:

```
$ git clone https://github.com/lann/devcrypt
$ cd devcrypt
$ go build
$ ./devcrypt help
```

### Generate a key for yourself

```
$ devcrypt keygen
Generating key with label "lann@computer"...
Wrote private key to "/home/lann/.config/devcrypt/devcrypt_key"
Wrote public key to "/home/lann/.config/devcrypt/devcrypt_key.pub"
Public key:
devcrypt-key cpCWOPP0/afWR3YkfrxZ6KptOO9pAZflm3LF6ChoTXU= lann@computer
```

### Encrypt your secrets

```
$ echo "SECRET_KEY=topSecret" > .env
$ devcrypt encrypt .env
Encrypted to ".env.devcrypt"
```

### Add a friend to your encrypted file

```
$ devcrypt keygen -k bobs_key -l bob@boblandia
...
Wrote public key to "bobs_key.pub"
...
$ devcrypt add .env.devcrypt bobs_key.pub
Adding public key labeled "bob@boblandia"
Updated ".env.devcrypt"
```

### Decrypt your secrets

```
$ devcrypt decrypt .env.devcrypt
Decrypted to ".env"
```

### Remove a friend (or enemy?) from your encrypted file

```
$ devscript rm .env.devcrypt lann@computer
Removing public key by label "lann@computer":
devcrypt-key cpCWOPP0/afWR3YkfrxZ6KptOO9pAZflm3LF6ChoTXU= lann@computer

Updated ".env.devcrypt"

$ devscript decrypt .env.devcrypt
Error: unsealing file: no key box found for key labeled "lann@computer"
```

## Cryptography

DevCrypt uses cryptographic elements from NaCl as implemented in
[golang.org/x/crypto/nacl](https://pkg.go.dev/golang.org/x/crypto/nacl).

Files are encryped with [secretbox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox)
using a random "file key". That key is then encrypted into one or more
"[sealed boxes](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes)",
which allow encryption with a public key and decryption with the matching private key.
The sealed boxes and matching public keys are stored along with the encrypted file in a single text file.

Users with private keys that match one of the "sealed boxes" can decrypt the file by looking up the sealed
box based on their public key, decrypting the file key using their private key, then decrypting the file
contents with the file key. They can also add new public keys to the encrypted file by decrypting the file
key and then reencrypting it into a new sealed box.
