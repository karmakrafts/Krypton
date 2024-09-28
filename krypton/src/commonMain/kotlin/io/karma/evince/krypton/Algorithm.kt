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
import kotlin.jvm.JvmStatic

/**
 * This enum represents all algorithms definitely supported by all platforms of the Krypton API. These are (a)symmetric
 * encryption algorithms and key agreements. It contains post-quantum algorithms like CRYSTALS-Dilithium and algorithms
 * which can be broken by quantum computers like ECDH or RSA.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
enum class Algorithm(
    private val literal: String,
    val supportedBlockModes: Array<BlockMode>,
    val supportedPaddings: Array<Padding>,
    val isBitSizeSupported: (Int) -> Boolean,
    val defaultBitSize: Int,
    val defaultBlockMode: BlockMode?,
    val defaultPadding: Padding?,
    val scopes: Array<Scope>,
    internal val supportedPlatforms: Array<Platform>
) {
    /**
     * This value represents the MD5 algorithm. MD5 is a deprecated standard for hashing and should not be used in
     * security relevant usage.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     */
    @Deprecated("MD5 is deprecated <https://en.wikipedia.org/wiki/MD5#Overview_of_security_issues>")
    MD5(
        literal = "MD5",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        isBitSizeSupported = { true },
        defaultBitSize = 128,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.DIGEST),
        supportedPlatforms = Platform.entries.filter { !it.isJS() }.toTypedArray()
    ),

    /**
     * This value represents the SHA1 algorithm. SHA1 is a deprecated standard for hashing and should not be used in
     * security relevant usage.
     *
     * @author Cedric Hames
     * @since  28/09/2024
     */
    @Deprecated("SHA-1 is deprecated <https://en.wikipedia.org/wiki/SHA-1>")
    SHA1(
        literal = "SHA-1",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        isBitSizeSupported = { true },
        defaultBitSize = 160,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.DIGEST),
        supportedPlatforms = Platform.entries.toTypedArray()
    ),
    
    /**
     * This value represents the 224-bit output length variant of the SHA (Secure Hash Algorithm) standard, also named
     * Keccak. This version of the standard is deprecated and SHA3 should be used.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-1](https://en.wikipedia.org/wiki/SHA-1)
     */
    SHA224(
        literal = "SHA-224",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        isBitSizeSupported = { true },
        defaultBitSize = 224,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.DIGEST),
        supportedPlatforms = Platform.entries.toTypedArray()
    ),
    
    /**
     * This value represents the 256-bit output length variant of the SHA (Secure Hash Algorithm) standard, also named
     * Keccak. This version of the standard is deprecated and SHA3 should be used.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-1](https://en.wikipedia.org/wiki/SHA-1)
     */
    SHA256(
        literal = "SHA-256",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        isBitSizeSupported = { true },
        defaultBitSize = 256,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.DIGEST),
        supportedPlatforms = Platform.entries.toTypedArray()
    ),
    
    /**
     * This value represents the 384-bit output length variant of the SHA (Secure Hash Algorithm) standard, also named
     * Keccak. This version of the standard is deprecated and SHA3 should be used.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-1](https://en.wikipedia.org/wiki/SHA-1)
     */
    SHA384(
        literal = "SHA-384",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        isBitSizeSupported = { true },
        defaultBitSize = 384,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.DIGEST),
        supportedPlatforms = Platform.entries.toTypedArray()
    ),
    
    /**
     * This value represents the 512-bit output length variant of the SHA (Secure Hash Algorithm) standard, also named
     * Keccak. This version of the standard is deprecated and SHA3 should be used.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-1](https://en.wikipedia.org/wiki/SHA-1)
     */
    SHA512(
        literal = "SHA-512",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        isBitSizeSupported = { true },
        defaultBitSize = 512,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.DIGEST),
        supportedPlatforms = Platform.entries.toTypedArray()
    ),
    
    /**
     * This value represents the 224-bit output length variant of the SHA3 (Secure Hash Algorithm) standard, also named
     * Keccak. SHA3 is the newest version of the SHA standard.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-3](https://en.wikipedia.org/wiki/SHA-3)
     */
    SHA3_224(
        literal = "SHA3-224",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        isBitSizeSupported = { true },
        defaultBitSize = 224,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.DIGEST),
        supportedPlatforms = Platform.entries.filter { !it.isJS() }.toTypedArray()
    ),
    
    /**
     * This value represents the 256-bit output length variant of the SHA3 (Secure Hash Algorithm) standard, also named
     * Keccak. SHA3 is the newest version of the SHA standard.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-3](https://en.wikipedia.org/wiki/SHA-3)
     */
    SHA3_256(
        literal = "SHA3-256",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        isBitSizeSupported = { true },
        defaultBitSize = 256,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.DIGEST),
        supportedPlatforms = Platform.entries.filter { !it.isJS() }.toTypedArray()
    ),
    
    /**
     * This value represents the 384-bit output length variant of the SHA3 (Secure Hash Algorithm) standard, also named
     * Keccak. SHA3 is the newest version of the SHA standard.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-3](https://en.wikipedia.org/wiki/SHA-3)
     */
    SHA3_384(
        literal = "SHA3-384",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        isBitSizeSupported = { true },
        defaultBitSize = 384,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.DIGEST),
        supportedPlatforms = Platform.entries.filter { !it.isJS() }.toTypedArray()
    ),
    
    /**
     * This value represents the 512-bit output length variant of the SHA3 (Secure Hash Algorithm) standard, also named
     * Keccak. SHA3 is the newest version of the SHA standard.
     *
     * @author Cedric Hammes
     * @since  19/09/2024
     *
     * @see [SHA-3](https://en.wikipedia.org/wiki/SHA-3)
     */
    SHA3_512(
        literal = "SHA3-512",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        isBitSizeSupported = { true },
        defaultBitSize = 512,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.DIGEST),
        supportedPlatforms = Platform.entries.filter { !it.isJS() }.toTypedArray()
    ),
    
    /**
     * The RSA (Rivest-Shamir-Adleman) algorithm is an asymmetric encryption and signature crypto system created in
     * 1977 by Ron Rivest, Adi Shamir and Leonard Adleman. According to the NIST's Recommendation for Key Management
     * the key length 2048 is recommended. Most security recommendations recommend elliptic curve cryptography over
     * the usage of RSA because of the smaller keys in relation to its security.
     *
     * This algorithm is based on the factoring problem, the difficulty of factoring the product of two large prime
     * numbers. No efficient algorithm is known for regular computer architectures but on quantum architectures the
     * Shor's algorithm, an algorithm for the efficient factorisation, is available.
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
        supportedBlockModes = arrayOf(BlockMode.ECB),
        supportedPaddings = arrayOf(Padding.NONE, Padding.PKCS5, Padding.OAEP_SHA1, Padding.OAEP_SHA256),
        supportedBitSizes = intArrayOf(1024, 2048, 4096, 8192),
        defaultBitSize = 4096,
        defaultBlockMode = BlockMode.ECB,
        defaultPadding = Padding.OAEP_SHA256,
        scopes = arrayOf(Scope.CIPHER, Scope.SIGNATURE, Scope.KEYPAIR_GENERATOR),
        supportedPlatforms = Platform.entries.toTypedArray()
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
        supportedBlockModes = BlockMode.entries.toTypedArray(),
        supportedPaddings = arrayOf(Padding.NONE, Padding.PKCS1),
        supportedBitSizes = intArrayOf(128, 192, 256),
        defaultBitSize = 256,
        defaultBlockMode = BlockMode.CBC,
        defaultPadding = Padding.NONE,
        scopes = arrayOf(Scope.CIPHER, Scope.KEY_GENERATOR),
        supportedPlatforms = Platform.entries.toTypedArray()
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
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        supportedBitSizes = intArrayOf(1024, 2048, 3000, 4096, 8192),
        defaultBitSize = 2048,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.KEY_AGREEMENT, Scope.KEYPAIR_GENERATOR, Scope.PARAMETER_GENERATOR),
        supportedPlatforms = Platform.entries.toTypedArray()
    ),
    
    /**
     * @author Cedric Hammes
     * @since  27/09/2024
     */
    @UnstableKryptonAPI
    ECDSA(
        literal = "ECDSA",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        supportedBitSizes = intArrayOf(128, 192, 256),
        defaultBitSize = 256,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.KEYPAIR_GENERATOR, Scope.SIGNATURE),
        supportedPlatforms = Platform.entries.toTypedArray()
    ),
    
    /**
     * The ECDH (Elliptic-Curve Diffie-Hellman) is the elliptic-curve equivalent of the Diffie-Hellman key agreement
     * algorithm. The advantage of ECDH is the higher security with lower key sizes compared to DH. This algorithm
     * is used in the Signal Protocol and other implementations. It can be broken by Shor's algorithm.
     *
     * @author Cedric Hammes
     * @since  10/09/2024
     *
     * @see [Wikipedia, Elliptic-curve Diffie-Hellman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
     * @see [Wikipedia, Shor's Algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
     */
    ECDH(
        literal = "ECDH",
        supportedBlockModes = emptyArray(),
        supportedPaddings = emptyArray(),
        supportedBitSizes = intArrayOf(128, 192, 256),
        defaultBitSize = 256,
        defaultBlockMode = null,
        defaultPadding = null,
        scopes = arrayOf(Scope.KEY_AGREEMENT, Scope.KEYPAIR_GENERATOR),
        supportedPlatforms = Platform.entries.toTypedArray()
    );
    
    /** @suppress **/
    constructor(
        literal: String, supportedBlockModes: Array<BlockMode>, supportedPaddings: Array<Padding>,
        supportedBitSizes: IntArray, defaultBitSize: Int, defaultBlockMode: BlockMode?, defaultPadding: Padding?,
        scopes: Array<Scope>, supportedPlatforms: Array<Platform>
    ) : this(
        literal, supportedBlockModes, supportedPaddings, { value -> supportedBitSizes.contains(value) }, defaultBitSize, defaultBlockMode,
        defaultPadding, scopes, supportedPlatforms
    )

    /**
     * This function validates the current platform used and the scope specified. If one of these parameters are not matching this function
     * throws an exception.
     *
     * @author Cedric Hammes
     * @since  17/09/2024
     */
    fun validOrError(scope: Scope): Algorithm = this.also {
        if (!it.supportedPlatforms.contains(Platform.CURRENT))
            throw RuntimeException("Algorithm '$it' is not supported on platform '${Platform.CURRENT}'")
        if (!it.scopes.contains(scope)) {
            val supported = Algorithm.byScope(listOf(scope)).joinToString(", ")
            throw IllegalArgumentException("Algorithm '$literal' cannot be found for $scope. Please use: one of the following: $supported")
        }
    }
    
    /**
     * This function returns the algorithm as a literal. These literals are used internally for the JVM target.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     */
    override fun toString(): String = literal
    
    companion object {
        @JvmStatic
        fun firstOrNull(literal: String): Algorithm? = Algorithm.entries.firstOrNull { it.toString() == literal }
        
        @JvmStatic
        fun byScope(scopes: List<Scope>): List<Algorithm> =
            Algorithm.entries.filter { curr -> curr.scopes.all { it in scopes } }
    }
    
    /**
     * This class indicates the usages for cryptographic algorithms in the Krypton API. Al of these are checked by the
     * API to ensure the correct usage of keys.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     */
    enum class Scope(private val literal: String) {
        CIPHER("Cipher"),
        KEYPAIR_GENERATOR("Keypair Generator"),
        KEY_GENERATOR("Key Generator"),
        KEY_AGREEMENT("Key Agreement"),
        PARAMETER_GENERATOR("Parameter generator"),
        SIGNATURE("Signature"),
        DIGEST("Digest");
        
        override fun toString(): String = literal
    }
}

/**
 * This enum represents all block modes supported by block ciphers like AES or RSA.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
enum class BlockMode {
    ECB,
    CBC,
    CFB,
    OFB,
    OCB,
    CTR,
    GCM
}

/**
 * This enum represents all paddings support by ciphers.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
enum class Padding(private val literal: String, internal val digest: String?) {
    NONE("NoPadding", null),
    PKCS5("PKCS5Padding", null),
    PKCS1("PKCS1Padding", null),
    OAEP_SHA1("OAEPWithSHA-1AndMGF1Padding", "SHA-1"),
    OAEP_SHA256("OAEPWithSHA-256AndMGF1Padding", "SHA-256");
    
    override fun toString(): String = literal
}
