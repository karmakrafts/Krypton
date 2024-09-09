# Krypton
Krypton is a library that implements the cryptographic primitives like ciphers or hash functions into Kotlin Multiplatform. Below this text you can see a list of the implemented algorithms, hash functions and more:
- **Hash Functions:** SHA3 (224, 256, 384 and 512 bits), SHA (224, 256, 384 and 512 bits) and MD5
- **Ciphers:** AES (128, 192 and 256 bits), RSA, DES and Triple-DES
- **Key Agreements:** Diffie-Hellman (DH) and Elliptic Curve Diffie-Hellman (ECDH)
- **Elliptic curves:** All of supported by all platforms together and custom elliptic curves

## ToDo's
- [X] Keys, Key Generator and Keypair Generator
- [X] Hashing algorithms and digest
- [ ] Default curves and custom definable elliptic curve
- [ ] Cipher class for (a)symmetric encryption algorithms
- [ ] KeyAgreement class for key agreement algorithms
- [ ] Signature class for signature algorithms
- [ ] Rewrite supportedBitSize to bitSizePredicate and implement it into the key generators in Algorithm
- [ ] Post-quantum algorithms like CRYSTALS-Dilithium
- [ ] Key derivation functions (KDF) like HDKF
- [ ] Message Authentication Codes
- [ ] Support for dynamic-length hash functions like SHAKE-128