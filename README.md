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
  * Fingerprint of recipient key (20 bytes)
  * Fingerprint of sender key (20 bytes)
  * AES key (32 bytes)
  * Length of message below (4 bytes)
  * Message padding interval
  * {PKCS secure padding voodoo provided by OpenSSL}
* "Encrypted" with sender's private key
  * SHA-512 of encrypted message below
  * {PKCS secure padding voodoo provided by OpenSSL}
* Encrypted with AES key
  * Message

### Encryption process

* Generate an AES-256 key
* Pad message buffer to multiple of 256-bits
* Encrypt message with key
* Hash the encrypted message 
* `RSA_private_encrypt` the SHA with your key
* Concatenate the following:
  * Recipient key fingerprint
  * Sender key fingerprint
  * AES key from above
  * Length of original message (before padding)
* `RSA_public_encrypt` that data with the recipient's key
* Concatenate the following as the final message:
  * recipient-encrypted block
  * sender-encrypted block
  * encrypted message data

### Decryption Process

* `RSA_private_decrypt` the header
* Verify your key fingerprint
* Fetch sender's public key from their fingerprint
  * Validate trust, either via keybase or ???
* `RSA_public_decrypt` the signature
* Validate SHA of encrypted message
* Decrypt message
  * Based on length in header, discard any padding
  * AES decrypt remaining message
  * discard any block padding

### Code Components

| Module | Description |
| ------ | ----------- |
| `crypto/mod.rs` | Cryptographic operations (provided by libcrypto) |
| `crypto/ffi.rs` | low-level bindings to libcrypto |
| `keybase.rs` | Keybase API bindings |
| `lib.rs` | High-level hedwig operations |
| `pubsub.rs` | Hedwig message sending and fetching |
| `pgp.rs` | PGP (potentially armored) V4 packet parsing |
| `bin/hedwig_send.rs` | A CLI frontend for sending a hedwig message |
| `bin/hedwig_recv.rs` | A CLI frontend for fetching hedwig messages |
