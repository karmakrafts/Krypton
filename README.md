# Krypton
Krypton is a library that implements the cryptographic primitives like ciphers or hash functions into Kotlin Multiplatform. This library uses the system dependency and other external library's for the implementations to reduce the risk of more bugs in the cryptological core. Below this text you can see a list of the implemented algorithms, hash functions and more:
- **Hash Functions:** SHA3 (224, 256, 384 and 512 bits), SHA (224, 256, 384 and 512 bits) and MD5
- **Ciphers:** AES (128, 192 and 256 bits), RSA, DES and Triple-DES
- **Key Agreements:** Diffie-Hellman (DH) and Elliptic Curve Diffie-Hellman (ECDH)
- **Elliptic curves:** All curves supported by all platforms together and custom elliptic curves

Below this text you can see the list of backends used on different platforms:
- **Linux:** [OpenSSL](https://www.openssl.org/) ([Apache License 2.0](https://github.com/openssl/openssl/blob/master/LICENSE.txt)) by The OpenSSL Project
- **JVM:** [Java Cryptography Architecture](https://en.wikipedia.org/wiki/Java_Cryptography_Architecture) ([Oracle Binary Code License](https://www.oracle.com/downloads/licenses/binary-code-license.html)) by Oracle and Sun Microsystems and [BouncyCastle](https://github.com/bcgit/bc-java) ([MIT License](https://github.com/bcgit/bc-java/blob/main/LICENSE.md)) by [Legion of the Bouncy Castle Inc](https://github.com/bcgit)

## ToDo's
- [X] Keys, Key Generator and Keypair Generator
- [X] Hashing algorithms and digest
- [X] Default curves and custom definable elliptic curve
- [ ] Cipher class for (a)symmetric encryption algorithms
- [X] KeyAgreement class for key agreement algorithms
- [ ] Signature class for signature algorithms
- [X] Rewrite supportedBitSize to bitSizePredicate and implement it into the key generators in Algorithm
- [ ] Post-quantum algorithms like CRYSTALS-Dilithium
- [ ] Key derivation functions (KDF) like HDKF
- [ ] Message Authentication Codes
- [ ] Support for dynamic-length hash functions like SHAKE-128
- [ ] Add support for key stores