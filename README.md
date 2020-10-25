p256.js
=======

This is a simple utility library for use with the `P-256` (aka `prime256v1`,
aka `secp256r1`) elliptic curve and the
[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

Particularly motivation limitations of the Web Crypto API were inability to
import a private key scalar without already knowing the corresponding public
point, and the lack of support for compressed public keys.

The code will register `P256` as a global variable, with a number of static
methods depending on build configuration.

Minimal size was a goal. Most of the math is handled by Tom Wu’s well known
library `jsbn`, which has been stripped down to remove unneeded functionality.
Basically no data validation is done.

**WARNING:** I do not intend to spend much, if any, time maintaining this code.
Use at your own risk, etc.

Functions Available
-------------------

Most of the functions are self-explanatory in usage.

All functions that need a “byte array” input will accept a standard `Array`, a
`TypedArray`, a `DataView`, or an `ArrayBuffer`.

### `P256.jwkToPrivate(jwk)`

Takes in an exported JWK object, gives the private key scalar as a 32 byte
`Uint8Array`.

### `P256.jwkToPublic(jwk)`

Takes in an exported JWK object, gives the public point in compressed format as
a 33 byte `Uint8Array`.

### `P256.privateToJwk(byteArray)`

Takes in a 32 byte array containing a private key scalar, returns a JWK object
that can be imported.

### `P256.publicToJwk(byteArray)`

Takes in a 65 or 33 byte array containing a public point in uncompressed,
compressed, or hybrid format; returns a JWK object that can be imported.

### `P256.pkcs8ToPrivate(byteArray)`

Takes in an exported PKCS8 byte array, gives the private key scalar as a 32
byte `Uint8Array`.

### `P256.spkiToPublic(byteArray)`

Takes in an exported SubjectPublicKeyInfo byte array, gives the public point in
compressed format as a 33 byte `Uint8Array`.

### `P256.privateToPkcs8(byteArray)`

Takes in a 32 byte array containing a private key scalar, returns an `ArrayBuffer`
with that key encoded in PKCS8 format that can be imported.

### `P256.publicToSpki(byteArray)`

Takes in a 65 or 33 byte array containing a public point in uncompressed,
compressed, or hybrid format; returns an `ArrayBuffer` with that point encoded
in SubjectPublicKeyInfo format that can be imported.

### `P256.invertPrivate(byteArray)`

Takes in a 32 byte array containing a private key scalar, returns a 32 byte
array with a negated copy of that key. This is useful if you want to switch
the y coordinate of the public point between being even and odd.

### `P256.checkPrivate(byteArray)`

Takes in a 32 byte array containing a private key scalar, returns true if it
is “valid”, false otherwise.

### `P256.seedToPrivate(byteArray, callback)`

Takes in a byte array containing arbitrary data, calls callback function with
a 32 byte `Uint8Array` filed with a valid private key scalar deterministically
generated from the seed data. If you use this with passwords or passphrases as
inputs terrible things will happen.

