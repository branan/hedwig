[![Build Status](https://travis-ci.org/branan/hedwig.png?branch=master)](https://travis-ci.org/branan/hedwig)
[![Coverage Status](https://coveralls.io/repos/branan/hedwig/badge.svg?branch=master&service=github)](https://coveralls.io/github/branan/hedwig?branch=master)

# Hedwig

Hedwig is a utility and protocol for provding ENCRYPTED and ANONYMOUS
communication. It does this by encrypting sender and recipient
identity information in such a way that only the intended recipient
can read them.

In order to implement this, clients must sync ALL messages in the
hedwig ecosystem. We are working to understand how to do this in a way
that prevents (or at least discourages) DOS attacks.

## Short term goals

* An implementation of the hedwig message protocol (described below)
* A CLI interface to Hedwig for sending and receiving messages
* A simple service for replicating messages between clients
* Keybase integration to retrieve key material

## Long term goals

* Local GPG integration to retrieve key material
* PGP keyserver integration to retrieve key material
* A replication service that discourages DOSing/spamming
  * Can we require a proof-of-work here? A blockchain of some sort maybe?
* Additional UIs / messaging integrations

## Technical gibberish

### Message Format

* Encrypted with recipient's public key
  * AES key (16 bytes)
  * AES CFB IV (16 bytes)
  * Fingerprint of recipient key (20 bytes)
  * Fingerprint of sender key (20 bytes)
  * {PKCS secure padding}
* Signed with sender's private key
  * SHA1 of plaintext message
  * {PKCS secure padding}
* Encrypted with AES key
  * Message

### Encryption process

* Generate an AES-128 key
* Generate an IV for CFB mode
* Encrypt message with key
* Hash the encrypted message 
* Sign the SHA with your key
* Concatenate the following:
  * Recipient key fingerprint
  * Sender key fingerprint
  * AES key from above
  * CFB IV from above
* Encrypt that data with the recipient's key
* Concatenate the following as the final message:
  * recipient-encrypted block
  * sender-signed block
  * encrypted message data

### Decryption Process

* RSA Decrypt the header
* Verify your key fingerprint
* Fetch sender's public key from their fingerprint
  * Validate trust
* Verify the signature
* Validate SHA of encrypted message
* Decrypt message
  * AES decrypt remaining message
