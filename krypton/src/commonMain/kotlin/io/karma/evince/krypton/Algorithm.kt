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
import io.karma.evince.krypton.parameters.KeyGeneratorParameters

internal expect class DefaultHashProvider(algorithm: Algorithm) : Hash
internal expect class DefaultSymmetricCipher(algorithm: Algorithm) : KeyGenerator

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
    override val supportedPlatforms: Array<Platform> = Platform.entries.toTypedArray(),
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
        cryptoProvider = lazy { DefaultHashProvider(MD5) },
        supportedPlatforms = Platform.entries.filter { !it.isJS() }.toTypedArray()
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
        cryptoProvider = lazy { DefaultHashProvider(SHA1) }
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
        cryptoProvider = lazy { DefaultHashProvider(SHA224) }
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
        cryptoProvider = lazy { DefaultHashProvider(SHA256) }
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
        cryptoProvider = lazy { DefaultHashProvider(SHA384) }
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
        cryptoProvider = lazy { DefaultHashProvider(SHA512) }
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
        cryptoProvider = lazy { DefaultHashProvider(SHA3_224) },
        supportedPlatforms = Platform.entries.filter { !it.isJS() }.toTypedArray()
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
        cryptoProvider = lazy { DefaultHashProvider(SHA3_256) },
        supportedPlatforms = Platform.entries.filter { !it.isJS() }.toTypedArray()
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
        cryptoProvider = lazy { DefaultHashProvider(SHA3_384) },
        supportedPlatforms = Platform.entries.filter { !it.isJS() }.toTypedArray()
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
        cryptoProvider = lazy { DefaultHashProvider(SHA3_512) },
        supportedPlatforms = Platform.entries.filter { !it.isJS() }.toTypedArray()
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
        cryptoProvider = lazy { TODO() },
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
        defaultPadding = Algorithm.Padding.NONE,
        blockSize = 128U
    ),

    /**
     * The DH (Diffie-Hellman) algorithm is a key agreement algorithm created in 1976. This algorithm is used for the
     * key agreement in the TLS protocol. According to the NIST's Recommendation for Key Management the key length 2048
     * is recommended. It can be broken by Shor's algorithm.
     *
     * @author Cedric Hammes
     * @since  09/09/2024
     *
     * @see [Wikipedia, Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
     * @see [Wikipedia, Shor's Algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
     */
    DH(
        literal = "DH",
        cryptoProvider = lazy { TODO() },
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        supportedBitSizes = ushortArrayOf(1024U, 2048U, 4096U, 8192U)
    ),

    /**
     * The ECDH (Elliptic-Curve Diffie-Hellman) is the elliptic-curve equivalent of the Diffie-Hellman key agreement algorithm. The
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
        cryptoProvider = lazy { TODO() },
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        supportedBitSizes = ushortArrayOf(128U, 192U, 256U),
        defaultBlockMode = null,
        defaultPadding = null,
        supportedPlatforms = Platform.entries.toTypedArray()
    );

    constructor(
        literal: String,
        cryptoProvider: Lazy<CryptoProvider>,
        supportedBitSizes: UShortArray,
        blockSize: UShort? = null,
        supportedBlockModes: Array<Algorithm.BlockMode> = emptyArray(),
        supportedPlatforms: Array<Platform> = Platform.entries.toTypedArray(),
        supportedPaddings: Array<Algorithm.Padding> = emptyArray(),
        defaultBlockMode: Algorithm.BlockMode? = null,
        defaultPadding: Algorithm.Padding? = null
    ) : this(
        literal,
        cryptoProvider,
        { supportedBitSizes.contains(it) },
        blockSize,
        supportedBlockModes,
        supportedPlatforms,
        supportedPaddings,
        defaultBlockMode,
        defaultPadding
    )

    override fun toString(): String = literal
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
    val supportedPlatforms: Array<Platform>

    // Defaults
    val defaultPadding: Padding?
    val defaultBlockMode: BlockMode?

    suspend fun hash(input: String): ByteArray = hash(input.encodeToByteArray())
    suspend fun hashToString(input: String): String = hashToString(input.encodeToByteArray())
    @OptIn(ExperimentalStdlibApi::class)
    suspend fun hashToString(input: ByteArray): String = hash(input).toHexString()

    @Suppress("UNCHECKED_CAST")
    fun <T : CryptoProvider> cryptoProvider(scope: String): T {
        if (!supportedPlatforms.contains(Platform.CURRENT))
            throw KryptonException("Algorithm '$literal' is not supported on platform '${Platform.CURRENT}'")
        return (cryptoProvider.value as? T) ?: throw InitializationException("$scope function is not available for algorithm '$literal'")
    }

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
    suspend fun hash(input: ByteArray): ByteArray = cryptoProvider<Hash>("Hashing").hash(input)

    /**
     * This function validates whether this algorithm supports key generation by checking the crypto provider. If this check is successful
     * it takes the parameters and generates a key from it.
     *
     * TODO: Add parameters
     *
     * @param parameters The parameters used for the key generation
     * @return           The generated key
     *
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    suspend fun generateKey(parameters: KeyGeneratorParameters): Key = cryptoProvider<KeyGenerator>("Key generation")
        .generateKey(parameters)

    /**
     * This function validates whether this algorithm supports keypair generation by checking the crypto provider. If this check is
     * successful it takes the parameters and generates a key from it.
     *
     * TODO: Add parameters
     *
     * @return The generated private-public keypair
     *
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    suspend fun generateKeypair(): KeyPair = cryptoProvider<KeypairGenerator>("Keypair generation").generateKeypair()

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
    enum class Padding(private val literal: String, internal val digest: String?) {
        NONE("NoPadding", null),
        PKCS5("PKCS5Padding", null),
        PKCS1("PKCS1Padding", null),
        OAEP_SHA1("OAEPWithSHA-1AndMGF1Padding", "SHA-1"),
        OAEP_SHA256("OAEPWithSHA-256AndMGF1Padding", "SHA-256");

        override fun toString(): String = literal
    }

}
