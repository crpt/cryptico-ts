# cryptico

> Forked from [cryptico](https://github.com/tracker1/cryptico-js), ported to ES modules and TypeScript.

## Install

`npm install @daotl/cryptico`

```typescript
import { cryptico, RSAKey } from '@daotl/cryptico'
const key: RSAKey = cryptico.generateRSAKey('Made with love by DAOT Labs', 512)
```

If using in Node.js, you can instead use the [@daotl/cryptico-node](https://www.npmjs.com/package/@daotl/cryptico-node) package (same API) for better performance, which use Node.js standard library `crypto` for hashing instead of native JavaScript implementation.

To use with plain HTML and JavaScript, include [dist/cryptico.iife.js](dist/cryptico.iife.js) (example from [test/test.html](test/test.html)):
```HTML
<script language="JavaScript" type="text/javascript" src="../dist/cryptico.iife.js"></script>
<script lang="js">
  const api = cryptico.cryptico
  const key = api.generateAESKey('Made with love by DAOT Labs', 512)
</script>
```

## Overview

### Generating an RSA key pair & public key string

Sam wants to send Matt an encrypted message.  In order to do this, he first needs Matt's public key string.  A public key pair can be generated for Matt like this:

```javascript
// The passphrase used to repeatably generate this RSA key.
var PassPhrase = "The Moon is a Harsh Mistress."; 

// The length of the RSA key, in bits.
var Bits = 1024; 

var MattsRSAkey = cryptico.generateRSAKey(PassPhrase, Bits);
```

Matt's public key string can then be generated like this:

```javascript
var MattsPublicKeyString = cryptico.publicKeyString(MattsRSAkey);       
```

and looks like this:
        
    uXjrkGqe5WuS7zsTg6Z9DuS8cXLFz38ue+xrFzxrcQJCXtVccCoUFP2qH/AQ
    4qMvxxvqkSYBpRm1R5a4/NdQ5ei8sE8gfZEq7dlcR+gOSv3nnS4/CX1n5Z5m
    8bvFPF0lSZnYQ23xlyjXTaNacmV0IuZbqWd4j9LfdAKq5dvDaoE=

### Encrypting a message

Matt emails Sam his public key string.  Now Sam can encrypt a message for Matt:

```javascript
var PlainText = "Matt, I need you to help me with my Starcraft strategy.";

var EncryptionResult = cryptico.encrypt(PlainText, MattsPublicKeyString);
```

`EncryptionResult.cipher` is the encrypted message, and looks like this:

    OOHoAlfm6Viyl7afkUVRoYQv24AfdLnxaay5GjcqpxvEK+dph5kUFZEZIFKo
    vVoHoZbtUMekSbMqHQr3wNNpvcNWr4E3DgNLfMZQA1pCAUVmPjNM1ZQmrkKY
    HPKvkhmVKaBiYAJGoO/YiFfKnaylLpKOYJZctkZc4wflZcEEqqg=?cJPt71I
    HcU5c2LgqGXQKcx2BaAbm25Q2Ku94c933LX5MObL9qbTJEVEv29U0C3gIqcd
    qwMV6nl33GtHjyRdHx5fZcon21glUKIbE9P71NwQ=

### Decrypting a message
    
Sam sends his encrypted message to Matt. The message can be decrypted like this:
    
```javascript
var CipherText = "OOHoAlfm6Viyl7afkUVRoYQv24AfdLnxaay5GjcqpxvEK+dph5kUFZEZIFKo \
                  vVoHoZbtUMekSbMqHQr3wNNpvcNWr4E3DgNLfMZQA1pCAUVmPjNM1ZQmrkKY \
                  HPKvkhmVKaBiYAJGoO/YiFfKnaylLpKOYJZctkZc4wflZcEEqqg=?cJPt71I \
                  HcU5c2LgqGXQKcx2BaAbm25Q2Ku94c933LX5MObL9qbTJEVEv29U0C3gIqcd \
                  qwMV6nl33GtHjyRdHx5fZcon21glUKIbE9P71NwQ=";

var DecryptionResult = cryptico.decrypt(CipherText, MattsRSAkey);
```

The decrypted message is in `DecryptionResult.plaintext`.

### Signatures & Public Key IDs
    
If Sam's RSA key is provided to the `cryptico.encrypt` function, the message will be signed by him:
    
```javascript
var PassPhrase = "There Ain't No Such Thing As A Free Lunch."; 

var SamsRSAkey = cryptico.generateRSAKey(PassPhrase, 1024);

var PlainText = "Matt, I need you to help me with my Starcraft strategy.";

var EncryptionResult = cryptico.encrypt(PlainText, MattsPublicKeyString, SamsRSAkey);
```

The public key associated with the signature can be used by Matt to make sure that it was sent by Sam, but there are a lot of characters to examine in the key - it would be easy to make a mistake.  Instead, the public key string associated with the signature can be processed like this:
    
```javascript
var PublicKeyID = cryptico.publicKeyID(EncryptionResult.cipher);
```

and `PublicKeyID` would look something like this:
    
    d0bffb0c422dfa3d3d8502040b915248

This shorter key ID can be used to uniquely identify Sam's public key more easily if it must be done manually.  Moreover, this key ID can be used by Sam or Matt to make sure they have typed their own passphrases correctly.
    
# API Documentation

## RSA Keys

    cryptico.generateRSAKey(passphrase, bitlength)

Generates an RSAKey object from a password and bitlength.

`passphrase`: string from which the RSA key is generated.

`bitlength`: integer, length of the RSA key (512, 1024, 2048, 4096, 8192).

Returns an `RSAKey` object.

    cryptico.publicKeyString(rsakey)

Returns the public key portion of an RSAKey object in ascii-armored
string form, which allows it to be used on websites and in text files
without fear of corrupting the public key.

`rsakey`: An `RSAKey` object.

Returns an ascii-armored public key string.
    
    cryptico.publicKeyID(publicKeyString)

Returns an MD5 sum of a `publicKeyString` for easier identification.

`publicKeyString`: a public key in ascii-armored string form, as generated by the `cryptico.publicKeyString` function.

Returns an MD5 sum of the public key string.   

## Encryption

    cryptico.encrypt(plaintext, publicKeyString, signingKey)

Encrypts a string with the provided public key. Optionally signs the encrypted string with an RSAKey object.

`plaintext`: the string to be encrypted.
    
`publicKeyString`: The public key string of the recipient.
    
`signingKey`: the `RSAKey` object of the sender.
    
Returns: `status`, `cipher`

`status`: "success" if encryption succeeded, "failure" if it failed.
    
`cipher`: An ascii-armored encrypted message string, optionally signed.

## Decryption

    cryptico.decrypt(ciphertext, key)

Decrypts an encrypted message with the recipient's RSAKey and verifies the signature, if any.

`ciphertext`: The encrypted message to be decrypted.
    
`key`: The `RSAKey` object of the recipient.

Returns: `status`, `plaintext`, `signature`, `publicKeyString`

`status`: "success" if decryption succeeded, "failure" if it failed. **Does not reflect the status of the signature verification.**

`plaintext`: The decrypted message.
    
`signature`: "unsigned" if there was no signature, "verified" if it is signed and valid, **"forged" if the signature fails verification**.

`publicKeyString`: public key string of the signature (presumably the sender). **Returned even if the signature appears to be forged**.

# Encryption Technical Documentation

## Key generation

A hash is generated of the user's passphrase using the SHA256 algorithm found at <a href="http://www.webtoolkit.info/javascript-sha256.html">webtoolkit.info</a>. This hash is used to seed <a href="http://davidbau.com/archives/2010/01/30/random_seeds_coded_hints_and_quintillions.html">David Bau's seedable random number generator</a>. A (seeded) random RSA key is generated with <a href="http://www-cs-students.stanford.edu/~tjw/jsbn/">Tom Wu's RSA key generator</a> with 3 as a hard-coded public exponent.

## Encryption

A 32-byte AES key is generated with <a href="http://www-cs-students.stanford.edu/~tjw/jsbn/">Tom Wu's random number generator</a>. The plaintext message is converted to a byte string and padded with zeros to 16 bytes round.  An initialization vector is created with <a href="http://www-cs-students.stanford.edu/~tjw/jsbn/">Tom Wu's random number generator</a>. The AES key is expanded and the plaintext message is encrypted with the Cipher-block chaining mode using the <a href="http://point-at-infinity.org/jsaes/">jsaes</a> library. The AES key is encrypted with the recipient's public key using <a href="http://www-cs-students.stanford.edu/~tjw/jsbn/">Tom Wu's RSA encryption library</a>.

The encrypted AES key and encrypted message are ascii-armored and concatenated with the "?" character as a delimiter.  As an example, here is the result of the phrase "Matt, I need you to help me with my Starcraft strategy." encrypted with
the passphrase "The Moon is a Harsh Mistress." used to generate the 1024-bit public key:

    EuvU2Ov3gpgM9B1I3VzEgxaAVO/Iy85NARUFZb/h+HrOP72degP0L1fWiHO3
    RDm5+kWRaV6oZsn91juJ0L+hrP6BDwlIza9x9DBMEsg3PnOHJENG63RXbu0q
    PZd2xDJY70i44sufNqHZ0mui9OdNIeE8FvzEOzMtFGCqDx1Z48s=?K3lOtQC
    2w+emoR4W3yvAaslSzTj/ZZIkOu3MNTW8y/OX0OxTKfpsaI6zX6XYrM0MpPr
    uw7on1N6VUMpNQO8KUVYl4clquaibKs0marXPFH4=

## Signing

When signing the encrypted message, two more pieces of information are attached to the cipher text.  The first is the ascii-armored RSA public key of the sender. The second piece of information concatenated with the cipher text is
the signature itself, which is generated with the <a href="http://www9.atwiki.jp/kurushima/pub/jsrsa/">rsa-sign extension by Kenji Urushima</a>, along with the SHA256 algorithm found at <a href="http://www.webtoolkit.info/javascript-sha256.html">webtoolkit.info</a>. These two pieces of code are also used when verifying the signature.

The signature is concatenated with the public key with the string
`::52cee64bb3a38f6403386519a39ac91c::` used as the delimiter between the
plaintext, the public key of the sender, and the signature:

    plaintext
    ::52cee64bb3a38f6403386519a39ac91c::
    public key of sender
    ::52cee64bb3a38f6403386519a39ac91c::
    signature

This concatenated block is then encrypted with CBC AES and concatenated with the
encrypted AES key to form the complete encrypted message.
