/*
 * Copyright 2024 Karma Krafts & associates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.karma.evince.krypton

import io.karma.evince.krypton.annotations.UnstableKryptonAPI
import io.karma.evince.krypton.parameters.CBCCipherParameters
import io.karma.evince.krypton.parameters.CipherParameters
import io.karma.evince.krypton.parameters.GCMCipherParameters
import io.karma.evince.krypton.parameters.KeyGeneratorParameters
import io.karma.evince.krypton.parameters.KeypairGeneratorParameters
import io.karma.evince.krypton.parameters.ParameterGeneratorParameters
import io.karma.evince.krypton.parameters.Parameters
import io.karma.evince.krypton.parameters.SignatureParameters

internal expect class DefaultHashProvider(algorithm: Algorithm) : Hash
internal expect class DefaultAsymmetricCipher(algorithm: Algorithm) : KeypairGenerator, CipherFactory, SignatureFactory
internal expect class DefaultSymmetricCipher(algorithm: Algorithm) : KeyGenerator, CipherFactory
internal expect class DefaultKeyAgreement(algorithm: Algorithm) : KeypairGenerator, ParameterGenerator, KeyAgreement
internal expect fun installRequiredProviders()

/**
 * This enum provides the by-default available algorithms surely supported by the Krypton library itself. This enum contains both deprecated
 * and new algorithms, also it provides access to quantum safe algorithms like **CRYSTALS-Kyber**. Most of the algorithms are standardized
 * and stabilized, the unstable ones are marked with [UnstableKryptonAPI].
 *
 * Below this text you can see a list of all algorithms supported by default (a few of them on not all platforms, mostly JS is not
 * supported by conditionally-supported algorithms):
 * - **Digests:** SHA-1, SHA-2 family, SHA-3 family and MD5
 * - **Key Agreement algorithm:** DH and ECDH
 * - **Signature algorithms:** RSA
 * - **Cipher algorithm:** RSA and RSA
 *
 * @author Cedric Hammes
 * @since  28/09/2024
 */
@OptIn(ExperimentalUnsignedTypes::class)
enum class DefaultAlgorithm(
    override val literal: String,
    override val cryptoProvider: Lazy<CryptoProvider>,
    override val bitSizePredicate: (UShort) -> Boolean = { true },
    override val blockSize: UShort? = null,
    override val supportedBlockModes: Array<Algorithm.BlockMode> = emptyArray(),
    override val supportedPaddings: Array<Algorithm.Padding> = emptyArray(),
    override val defaultBlockMode: Algorithm.BlockMode? = null,
    override val defaultPadding: Algorithm.Padding? = null
) : Algorithm {
    /**
     * This value represents the MD5 algorithm. MD5 is a deprecated standard for hashing and should not be used in
     * security relevant usage.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [MD5, Wikipedia](https://en.wikipedia.org/wiki/MD5#Overview_of_security_issues)
     */
    @Deprecated("MD5 is deprecated <https://en.wikipedia.org/wiki/MD5#Overview_of_security_issues>")
    MD5(
        literal = "MD5",
        cryptoProvider = @Suppress("DEPRECATION") lazy { DefaultHashProvider(MD5) }
    ),

    /**
     * This value represents the SHA1 algorithm. SHA1 is a deprecated standard for hashing and should not be used in security relevant
     * usage.
     *
     * @author Cedric Hammes
     * @since  28/09/2024
     *
     * @see [SHA-1, Wikipedia](https://en.wikipedia.org/wiki/SHA-1)
     */
    @Deprecated("SHA-1 is deprecated <https://en.wikipedia.org/wiki/SHA-1>")
    SHA1(
        literal = "SHA-1",
        cryptoProvider = @Suppress("DEPRECATION") lazy { DefaultHashProvider(SHA1) }
    ),

    /**
     * This value represents the 224-bit output variant of the second version of the Standard Hashing Algorithm (SHA) standard. SHA-2 is
     * not secure and there are practically-possible collision attack on This version so using SHA-3 (Keccak) is more recommended.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [Cryptanalysis and validation of SHA-2, Wikipedia](https://en.wikipedia.org/wiki/SHA-2#Cryptanalysis_and_validation)
     * @see [SHA-2, Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
     */
    @Deprecated("SHA-2 is deprecated <https://en.wikipedia.org/wiki/SHA>")
    SHA224(
        literal = "SHA-224",
        cryptoProvider = @Suppress("DEPRECATION") lazy { DefaultHashProvider(SHA224) }
    ),

    /**
     * This value represents the 256-bit output variant of the second version of the Standard Hashing Algorithm (SHA) standard. SHA-2 is
     * not secure and there are practically-possible collision attack on This version so using SHA-3 (Keccak) is more recommended.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [Cryptanalysis and validation of SHA-2, Wikipedia](https://en.wikipedia.org/wiki/SHA-2#Cryptanalysis_and_validation)
     * @see [SHA-2, Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
     */
    @Deprecated("SHA-2 is deprecated <https://en.wikipedia.org/wiki/SHA>")
    SHA256(
        literal = "SHA-256",
        cryptoProvider = @Suppress("DEPRECATION") lazy { DefaultHashProvider(SHA256) }
    ),

    /**
     * This value represents the 384-bit output variant of the second version of the Standard Hashing Algorithm (SHA) standard. SHA-2 is
     * not secure and there are practically-possible collision attack on This version so using SHA-3 (Keccak) is more recommended.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [Cryptanalysis and validation of SHA-2, Wikipedia](https://en.wikipedia.org/wiki/SHA-2#Cryptanalysis_and_validation)
     * @see [SHA-2, Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
     */
    @Deprecated("SHA-2 is deprecated <https://en.wikipedia.org/wiki/SHA>")
    SHA384(
        literal = "SHA-384",
        cryptoProvider = @Suppress("DEPRECATION") lazy { DefaultHashProvider(SHA384) }
    ),

    /**
     * This value represents the 512-bit output variant of the second version of the Standard Hashing Algorithm (SHA) standard. SHA-2 is
     * not secure and there are practically-possible collision attack on This version so using SHA-3 (Keccak) is more recommended.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [Cryptanalysis and validation of SHA-2, Wikipedia](https://en.wikipedia.org/wiki/SHA-2#Cryptanalysis_and_validation)
     * @see [SHA-2, Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
     */
    @Deprecated("SHA-2 is deprecated <https://en.wikipedia.org/wiki/SHA>")
    SHA512(
        literal = "SHA-512",
        cryptoProvider = @Suppress("DEPRECATION") lazy { DefaultHashProvider(SHA512) }
    ),

    /**
     * This value represents the 224-bit output variant of the third version of the Standard Hashing Algorithm (SHA) standard, also named
     * Keccak. Following to the current knowledge, SHA-3 is secure but can be broken by quantum attacks with Grover's algorithm. It is
     * recommended over the same variant over it's SHA-2 variant.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-3](https://en.wikipedia.org/wiki/SHA-3)
     */
    SHA3_224(
        literal = "SHA3-224",
        cryptoProvider = lazy { DefaultHashProvider(SHA3_224) }
    ),

    /**
     * This value represents the 256-bit output variant of the third version of the Standard Hashing Algorithm (SHA) standard, also named
     * Keccak. Following to the current knowledge, SHA-3 is secure but can be broken by quantum attacks with Grover's algorithm. It is
     * recommended over the same variant over it's SHA-2 variant.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-3](https://en.wikipedia.org/wiki/SHA-3)
     */
    SHA3_256(
        literal = "SHA3-256",
        cryptoProvider = lazy { DefaultHashProvider(SHA3_256) }
    ),

    /**
     * This value represents the 384-bit output variant of the third version of the Standard Hashing Algorithm (SHA) standard, also named
     * Keccak. Following to the current knowledge, SHA-3 is secure but can be broken by quantum attacks with Grover's algorithm. It is
     * recommended over the same variant over it's SHA-2 variant.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-3](https://en.wikipedia.org/wiki/SHA-3)
     */
    SHA3_384(
        literal = "SHA3-384",
        cryptoProvider = lazy { DefaultHashProvider(SHA3_384) }
    ),

    /**
     * This value represents the 512-bit output variant of the third version of the Standard Hashing Algorithm (SHA) standard, also named
     * Keccak. Following to the current knowledge, SHA-3 is secure but can be broken by quantum attacks with Grover's algorithm. It is
     * recommended over the same variant over it's SHA-2 variant.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-3](https://en.wikipedia.org/wiki/SHA-3)
     */
    SHA3_512(
        literal = "SHA3-512",
        cryptoProvider = lazy { DefaultHashProvider(SHA3_512) }
    ),

    /**
     * The RSA (Rivest-Shamir-Adleman) algorithm is an asymmetric encryption and signature crypto system created in 1977 by Ron Rivest, Adi
     * Shamir and Leonard Adleman. According to the NIST's recommendation for Key Management the key length 2048 is recommended. Most
     * security recommendations recommend elliptic curve cryptography over the usage of RSA because of the smaller keys in relation to its
     * security.
     *
     * This algorithm is based on the factoring problem, the difficulty of factoring the product of two large prime numbers. No efficient
     * algorithm is known for regular computer architectures but on quantum architectures the Shor's algorithm, an algorithm for the
     * efficient factorisation, is available.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     *
     * @see [Wikipedia, RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
     * @see [Wikipedia, Shor's Algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
     * @see [Wikipedia, Integer factorization](https://en.wikipedia.org/wiki/Integer_factorization)
     */
    RSA(
        literal = "RSA",
        cryptoProvider = lazy { DefaultAsymmetricCipher(RSA) },
        supportedBlockModes = arrayOf(Algorithm.BlockMode.ECB),
        supportedPaddings = arrayOf(
            Algorithm.Padding.NONE,
            Algorithm.Padding.PKCS5,
            Algorithm.Padding.OAEP_SHA1,
            Algorithm.Padding.OAEP_SHA256
        ),
        defaultPadding = Algorithm.Padding.OAEP_SHA256,
        defaultBlockMode = Algorithm.BlockMode.ECB
    ),

    /**
     * Ths AES (Advanced Encryption Standard, also known as Rijndael) block cipher is a symmetric encryption algorithm
     * created in 1998 with a block size of 128 bits. According to the NSA's Commercial National Security Algorithm
     * Suite the key length 256 is recommended. The security in bit can be reduced to the half by Grover's algorithm.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     *
     * @see [Wikipedia, AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
     * @see [Wikipedia, Grover's Algorithm](https://en.wikipedia.org/wiki/Grover%27s_algorithm)
     */
    AES(
        literal = "AES",
        cryptoProvider = lazy { DefaultSymmetricCipher(AES) },
        supportedBlockModes = Algorithm.BlockMode.entries.toTypedArray(),
        supportedPaddings = arrayOf(Algorithm.Padding.NONE, Algorithm.Padding.PKCS1),
        supportedBitSizes = ushortArrayOf(128U, 192U, 256U),
        defaultBlockMode = Algorithm.BlockMode.CBC,
        defaultPadding = Algorithm.Padding.PKCS5,
        blockSize = 128U
    ),

    /**
     * DH (Diffie-Hellman) is a key agreement algorithm created in 1976. This algorithm is used for the key agreement in the TLS protocol.
     * According to the NIST's Recommendation for Key Management the key length 2048 is recommended. It can be broken by Shor's algorithm.
     *
     * @author Cedric Hammes
     * @since  09/09/2024
     *
     * @see [Wikipedia, Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
     * @see [Wikipedia, Shor's Algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
     */
    DH(
        literal = "DH",
        cryptoProvider = lazy { DefaultKeyAgreement(DH) },
        supportedBitSizes = ushortArrayOf(1024U, 2048U, 4096U, 8192U)
    ),

    /**
     * ECDH (Elliptic-Curve Diffie-Hellman) is the elliptic-curve equivalent of the Diffie-Hellman key agreement algorithm. The
     * advantage of ECDH is the higher security with lower key sizes compared to DH. This algorithm is used in the Signal Protocol and
     * other implementations. It can be broken by Shor's algorithm.
     *
     * @author Cedric Hammes
     * @since  10/09/2024
     *
     * @see [Wikipedia, Elliptic-curve Diffie-Hellman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
     * @see [Wikipedia, Shor's Algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
     */
    ECDH(
        literal = "ECDH",
        cryptoProvider = lazy { DefaultKeyAgreement(ECDH) },
        supportedBitSizes = ushortArrayOf(128U, 192U, 256U)
    ),

    /**
     * PBKDF2 (Password-based key derivation function 2) is a key derivation function (KDF) with a computational cost. Like HKDF, PBKDF2 is
     * widely available in almost all programming languages and ecosystems. PBKDF2 comes with a few weaknesses and other candidates like
     * HKDF or Argon2 should be preferred over PBKDF2.
     *
     * @author Cedric Hammes
     * @since  30/09/2024
     *
     * @see [Wikipedia, PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)
     */
    @Deprecated("PBKDF2 should not be used <https://en.wikipedia.org/wiki/PBKDF2#Alternatives_to_PBKDF2>")
    PBKDF2(
        literal = "PBKDF2",
        cryptoProvider = lazy { TODO() }
    ),

    /**
     * HKDF is a key derivation function (KDF) based on the HMAC (Hash-based message authentication code) message authentication code and is
     * widely available in almost all programming languages and ecosystems. HDKF follows the extract-then expand paradigm by extracting a
     * pseudorandom key out of the data and then expand the key into several pseudorandom keys.
     *
     * @author Cedric Hammes
     * @since  30/09/2024
     *
     * @see [Wikipedia, HKDF](https://en.wikipedia.org/wiki/HKDF)
     * @see [Wikipedia, MAC](https://en.wikipedia.org/wiki/Message_authentication_code)
     * @see [Wikipedia, HMAC](https://en.wikipedia.org/wiki/HMAC)
     */
    HKDF(
        literal = "HKDF",
        cryptoProvider = lazy { TODO() },
    ),

    /**
     * Argon2i is a side-channel resistant variant of the Argon2 key derivation function (KDF) and the winner of the 2015 Password Hashing
     * Competition. Against this variant 2 cryptanalysis are available.but one is only applicable to an old version.
     *
     * @author Cedric Hammes
     * @since  30/09/2024
     *
     * @see [IETF, RFC9106](https://datatracker.ietf.org/doc/html/rfc9106)
     * @see [Wikipedia, Argon2](https://en.wikipedia.org/wiki/Argon2)
     */
    Argon2i(
        literal = "Argon2i",
        cryptoProvider = lazy { TODO() }
    ),

    /**
     * Argon2d is a GPU cracking attack resistant variant of the Argon2 key derivation function (KDF) and the winner of the 2015 Password
     * Hashing Competition. No public cryptanalysis against Argon2d is available but it introduces possibilities against side-channel
     * attacks.
     *
     * @author Cedric Hammes
     * @since  30/09/2024
     *
     * @see [IETF, RFC9106](https://datatracker.ietf.org/doc/html/rfc9106)
     * @see [Wikipedia, Argon2](https://en.wikipedia.org/wiki/Argon2)
     */
    Argon2d(
        literal = "Argon2d",
        cryptoProvider = lazy { TODO() }
    ),

    /**
     * Argon2id is a hybrid variant of the Argon2 key derivation function (KDF) and the winner of the 2015 Password Hashing Competition that
     * provides security against side-channel attacks and GPU cracking attacks. If side-channel attacks are a viable threat on your setup,
     * RFC 9106 recommends the usage of Argon2id.
     *
     * @author Cedric Hammes
     * @since  30/09/2024
     *
     * @see [IETF, RFC9106](https://datatracker.ietf.org/doc/html/rfc9106)
     * @see [Wikipedia, Argon2](https://en.wikipedia.org/wiki/Argon2)
     */
    Argon2id(
        literal = "Argon2id",
        cryptoProvider = lazy { TODO() }
    );

    constructor(
        literal: String,
        cryptoProvider: Lazy<CryptoProvider>,
        supportedBitSizes: UShortArray,
        blockSize: UShort? = null,
        supportedBlockModes: Array<Algorithm.BlockMode> = emptyArray(),
        supportedPaddings: Array<Algorithm.Padding> = emptyArray(),
        defaultBlockMode: Algorithm.BlockMode? = null,
        defaultPadding: Algorithm.Padding? = null
    ) : this(
        literal,
        cryptoProvider,
        { supportedBitSizes.contains(it) },
        blockSize,
        supportedBlockModes,
        supportedPaddings,
        defaultBlockMode,
        defaultPadding
    )

    companion object {
        init {
            installRequiredProviders()
        }
    }
}

/**
 * This interface is the implementation for an algorithm. This interface allows the developer to implement own algorithms into the API or
 * use algorithms exposed by a platform-specific backend that is not exposed by Krypton. We provide a wide range of default-supported
 * algorithms.
 *
 * @author Cedric Hammes
 * @since  28/09/2024
 */
interface Algorithm {
    val literal: String
    val bitSizePredicate: (UShort) -> Boolean
    val blockSize: UShort?
    val cryptoProvider: Lazy<CryptoProvider>

    // Supported
    val supportedBlockModes: Array<BlockMode>
    val supportedPaddings: Array<Padding>

    // Defaults
    val defaultPadding: Padding?
    val defaultBlockMode: BlockMode?

    suspend fun hash(input: String): ByteArray = hash(input.encodeToByteArray())
    suspend fun hashToString(input: String): String = hashToString(input.encodeToByteArray())
    @OptIn(ExperimentalStdlibApi::class)
    suspend fun hashToString(input: ByteArray): String = hash(input).toHexString()

    /**
     * This function uses the specified type to check if this algorithm supports the operation chosen by the developer. If yes, the provider
     * type is being casted into T, otherwise this function returns an exception.
     *
     * @param scope The scope name of the crypto provider
     * @param T     The provider type requested
     * @retun       The provider casted into T
     *
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    @Suppress("UNCHECKED_CAST")
    fun <T : CryptoProvider> cryptoProvider(scope: String): T = (cryptoProvider.value as? T)
        ?: throw InitializationException("$scope function is not available for algorithm '$literal'")

    /**
     * This function validates whether this algorithm supports hashing by checking the crypto provider. If this check is successful it takes
     * the input data and hashes it to another bytearray.
     *
     * @param input The input of the hash function
     * @return      The output of the hash function (the hash)
     *
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    fun hash(input: ByteArray): ByteArray = cryptoProvider<Hash>("Hashing").hash(input)

    /**
     * This function validates whether this algorithm supports key generation by checking the crypto provider. If this check is successful
     * it takes the parameters and generates a key from it.
     *
     * @param parameters The parameters used for the key generation
     * @return           The generated key
     *
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    fun generateKey(parameters: KeyGeneratorParameters): Key = cryptoProvider<KeyGenerator>("Key generation")
        .generateKey(parameters)

    /**
     * This function validates whether this algorithm supports keypair generation by checking the crypto provider. If this check is
     * successful it takes the parameters and generates a key from it.
     *
     * @param parameters THe parameters of the keypair generator instance
     * @return           The generated private-public keypair
     *
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    fun generateKeypair(parameters: KeypairGeneratorParameters): Keypair = cryptoProvider<KeypairGenerator>("Keypair generation")
        .generateKeypair(parameters)

    /**
     * This function takes the specified parameters and generate a cipher instance out of it. Based on the parameters, the instance can be
     * used to encrypt or decrypt data.
     *
     * @param parameters The parameters of the cipher instance
     * @return           The cipher instance
     *
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    fun createCipher(parameters: CipherParameters): Cipher = cryptoProvider<CipherFactory>("Cipher factory").createCipher(parameters)

    /**
     * This function takes the specified parameters and generate a signature instance out of it. Based on the parameters, the instance can
     * be used to sign data or verify signatures.
     *
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    fun createSignature(parameters: SignatureParameters): Signature = cryptoProvider<SignatureFactory>("Signature factory")
        .createSignature(parameters)

    /**
     * This function takes the two keys and computes a shared secret out of it. This secret should not be used as the key for the future
     * connection. It is recommended to put this array into a key derivation function.
     *
     * @param privateKey    Your own private key used for the key agreement
     * @param peerPublicKey The public key of the peer
     * @return              The computed secret
     *
     * @author Cedric Hammes
     * @since  30/09/2024
     */
    suspend fun computeSecret(privateKey: Key, peerPublicKey: Key): ByteArray = cryptoProvider<KeyAgreement>("Key agreement")
        .computeSecret(privateKey, peerPublicKey)

    /**
     * This function takes the parameters and generates secure parameters for the specified algorithm. These parameters are safe to use in
     * a environment where secure parameters for your cryptographic infrastructure are needed.
     *
     * @param parameters The parameters used for the parameter generation function
     * @param T          The type of the parameters generated
     *
     * @author Cedric Hammes
     * @since  30/09/2024
     */
    fun <T : Parameters> generateParameters(parameters: ParameterGeneratorParameters): T =
        cryptoProvider<ParameterGenerator>("Parameter generation").generateParameters(parameters)

    /**
     * This enum defines the block modes available in Krypton. Block modes are defining how a block cipher is encrypting data and can help
     * to ensure the authenticity of a message.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     *
     * @see [Block mode, Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
     */
    enum class BlockMode {
        /**
         * The electronic code bock (ECB) mode is the most unsecure mode of them and not recommended for the most algorithms. It runs all
         * blocks separately through the block cipher. This allows an attacker to recover data by muster analysis etc.
         *
         * @author Cedric Hammes
         * @since  08/09/2024
         */
        ECB,

        /**
         * The cipher block chaining (CBC) mode eliminates the attack vector of ECB by XORing the block with the encrypted output of the
         * last encrypted block. The first block is XORed with an initialization vector (IV), that should not be zeroed for maximum
         * security.
         *
         * @author Cedric Hammes
         * @since  08/09/2024
         *
         * @see [CBCCipherParameters]
         */
        CBC,

        /**
         * The output feedback (OCB) mode is like the CBC mode but with two differences. It encrypts the IV in the first block and run XOR
         * over the output and the plaintext. The output of This operation get encrypted and XORed with the next block.
         *
         * @author Cedric Hammes
         * @since  08/09/2024
         */
        OFB,

        /**
         * The counter (CTR) mode is using a nonce and counter which is being encrypted and XORed with the plaintext to encrypt the
         * plaintext.
         *
         * @author Cedric Hammes
         * @since  08/09/2024
         */
        CTR,

        /**
         * The Galois/Counter (GCM) mode is a block mode that uses authenticated encryption with associated data (AEAD) and requires an IV
         * and outputs a auth tag that is being used in the decryption process.
         *
         * @author Cedric Hammes
         * @since  08/09/2024
         *
         * @see [Galois/Counter mode, Wikipedia](https://de.wikipedia.org/wiki/Galois/Counter_Mode)
         * @see [GCMCipherParameters]
         */
        GCM
    }

    /**
     * This enum represents the padding mechanism by the cipher etc. In algorithm the supported and the default padding for the specific
     * algorithm is specified. Some of these paddings are based on digests like SHA-1.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     *
     * @see [Padding, Wikipedia](https://en.wikipedia.org/wiki/Padding_(cryptography))
     */
    enum class Padding(private val literal: String, internal val digest: String?, internal val genericName: String) {
        NONE("NoPadding", null, "NONE"),
        PKCS5("PKCS5Padding", null, "PKCS5"),
        PKCS7("PKCS7Padding", null, "PKCS7"), // TODO: This is the only available on JS for AES-GCM
        PKCS1("PKCS1Padding", null, "PKCS1"),
        OAEP_SHA1("OAEPWithSHA-1AndMGF1Padding", "SHA-1", "OAEP"),
        OAEP_SHA256("OAEPWithSHA-256AndMGF1Padding", "SHA-256", "OAEP");

        override fun toString(): String = literal
    }
}
