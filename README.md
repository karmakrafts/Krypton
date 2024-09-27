# Krypton - KMP Cryptography Library

Krypton is a library that implements the cryptographic primitives like ciphers or hash functions into Kotlin
Multiplatform. This library uses the system dependency and other external library's for the implementations to reduce
the risk of more bugs in the cryptological core. Below this text you can see a list of the implemented algorithms, hash
functions and more:

- **Hash Functions:** SHA3 (224, 256, 384 and 512 bits), SHA (224, 256, 384 and 512 bits) and MD5
- **Ciphers:** AES (128, 192 and 256 bits) and RSA
- **Signatures**: RSA (ECSDA is implemented but unstable)
- **Key Agreements:** Diffie-Hellman (DH) and Elliptic Curve Diffie-Hellman (ECDH)
- **Elliptic curves:** All curves supported by all platforms together

Below this text you can see the list of backends used on different platforms:

- **Native (Linux, Windows, macOS and iOS):** [OpenSSL](https://www.openssl.org/) ([Apache License 2.0](https://github.com/openssl/openssl/blob/master/LICENSE.txt)) by [The OpenSSL Project](https://github.com/OpenSSL/OpenSSL)
- **JVM:** [Java Cryptography Architecture](https://en.wikipedia.org/wiki/Java_Cryptography_Architecture) ([Oracle Binary Code License](https://www.oracle.com/downloads/licenses/binary-code-license.html)) by Oracle and Sun Microsystems and [BouncyCastle](https://github.com/bcgit/bc-java) ([MIT License](https://github.com/bcgit/bc-java/blob/main/LICENSE.md)) by [Legion of the Bouncy Castle Inc](https://github.com/bcgit)
- **JS:** [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) by [W3C](https://en.wikipedia.org/wiki/World_Wide_Web_Consortium)

## Credits

Some parts of this project are based on the work of other great people. In this part of the README I want to thank them and show a list of my inspirations etc.

- [trixnity-openssl-binaries](https://gitlab.com/trixnity/trixnity-openssl-binaries) - The OpenSSL binaries are acquired by the publications of this repository
- [trixnity-crypto-core](https://gitlab.com/trixnity/trixnity/-/tree/main/trixnity-crypto-core?ref_type=heads) - The integration of OpenSSL over multiple targets is heavily inspired that builscript code

### Dependencies

Also, a few dependencies are needed to make this project work. Below this text you can see a list of these project with author and license (by the time the dependency was added):

| Name                                                                   | Author                                                      | License                                                                                        | 
|------------------------------------------------------------------------|-------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| [Kotest](https://github.com/kotest/kotest)                             | [Kotest](https://github.com/kotest)                         | [Apache License 2.0](https://github.com/kotest/kotest/blob/master/LICENSE)                     |
| [okio](https://github.com/square/okio)                                 | [Square](https://github.com/square)                         | [Apache License 2.0](https://github.com/square/okio/blob/master/LICENSE.txt)                   |
| [bouncycastle-java](https://www.bouncycastle.org/repositories/bc-java) | [Legion of the Bouncycastle Inc.](https://github.com/bcgit) | [MIT License](https://github.com/bcgit/bc-java/blob/main/LICENSE.md)                           |
| [dokka](https://github.com/Kotlin/dokka)                               | [Kotlin](https://github.com/Kotlin)                         | [Apache License 2.0](https://github.com/Kotlin/dokka/blob/master/LICENSE.txt)                  |
| [bignum](https://github.com/ionspin/kotlin-multiplatform-bignum)       | [Ugljesa Jovanovic](https://github.com/ionspin)             | [Apache License 2.0](https://github.com/ionspin/kotlin-multiplatform-bignum/blob/main/LICENSE) |
| [OpenSSL](https://github.com/OpenSSL/OpenSSL)                          | [The OpenSSL Project](https://github.com/OpenSSL/OpenSSL)   | [Apache License 2.0](https://github.com/openssl/openssl/blob/master/LICENSE.txt)               |

## ToDo's

- [X] Keys, Key Generator and Keypair Generator
- [X] Hashing algorithms and digest
- [X] Default curves
- [X] Cipher class for (a)symmetric encryption algorithms
- [X] KeyAgreement class for key agreement algorithms
- [X] Signature class for signature algorithms
- [X] Rewrite supportedBitSize to bitSizePredicate and implement it into the key generators in Algorithm
- [ ] Post-quantum algorithms like
  CRYSTALS-Dilithium ([#3](https://git.karmakrafts.dev/kk/evince-project/krypton/-/issues/3))
- [ ] Key derivation functions (KDF) like HDKF
- [ ] Message Authentication Codes
- [ ] Support for dynamic-length hash functions like SHAKE-128
- [ ] Add support for key stores
- [ ] Custom elliptic curves ([#2](https://git.karmakrafts.dev/kk/evince-project/krypton/-/issues/2))
- [ ] Deprecated or unsecure ciphers like DES or Triple-DES

## License

This project is licensed with the Apache-2.0 License.

```
Copyright 2024 Karma Krafts & associates
  
Licensed under the Apache License, Version 2.0 (the "License");  
you may not use this file except in compliance with the License.  
You may obtain a copy of the License at  
  
    http://www.apache.org/licenses/LICENSE-2.0  
  
Unless required by applicable law or agreed to in writing, software  
distributed under the License is distributed on an "AS IS" BASIS,  
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
See the License for the specific language governing permissions and  
limitations under the License.
```
