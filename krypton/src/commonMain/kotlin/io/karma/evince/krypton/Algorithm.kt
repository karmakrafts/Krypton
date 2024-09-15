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

/**
 * This enum represents all algorithms definitely supported by all platforms of the Krypton API. These are (a)symmetric
 * encryption algorithms and key agreements. It contains post-quantum algorithms like CRYSTALS-Dilithium and algorithms
 * which can be broken by quantum computers like ECDH or RSA.
 *
 * TODO: Rewrite supportedBitSize to bitSizePredicate and implement it into the key generators
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
enum class Algorithm(
    private val literal: String,
    val supportedBlockModes: Array<BlockMode>?,
    val supportedPaddings: Array<Padding>?,
    val isBitSizeSupported: (Int) -> Boolean,
    val asymmetric: Boolean,
    val defaultBlockMode: BlockMode?,
    val defaultPadding: Padding?,
    val usages: Array<Usage>
) {
    /**
     * The RSA (Rivest-Shamir-Adleman) algorithm is an asymmetric encryption and signature crypto system created in
     * 1977. According to the NIST's Recommendation for Key Management the key length 2048 is recommended. It can be
     * broken by Shor's algorithm.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     *
     * @see [Wikipedia, RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
     * @see [Wikipedia, Shor's Algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
     */
    RSA(
        "RSA", arrayOf(BlockMode.ECB), arrayOf(
            Padding.NONE, Padding.PKCS5, Padding.OAEP_SHA1_MGF1,
            Padding.OAEP_SHA256_MGF1
        ), intArrayOf(1024, 2048, 4096, 8192), true,
        BlockMode.ECB, Padding.PKCS5,
        arrayOf(Usage.CIPHER, Usage.SIGNATURE)
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
        "AES", BlockMode.entries.toTypedArray(), arrayOf(Padding.NONE, Padding.PKCS1), intArrayOf(128, 192, 256), false,
        BlockMode.CBC, Padding.NONE,
        arrayOf(Usage.CIPHER)
    ),

    /**
     * The DES (Data Encryption Standard) block cipher is a symmetric encryption algorithm created in 1975 with a block
     * size of 64 bits. DES can be attacked by bruteforce easily and by multiple cryptanalytic attacks so the algorithm
     * is considered as deprecated and was replaced with Triple-DES and the algorithm AES is recommended for symmetric
     * encryption. The security in bit can be reduced to the half by Grover's algorithm.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     *
     * @see [Wikipedia, DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
     * @see [Wikipedia, Grover's Algorithm](https://en.wikipedia.org/wiki/Grover%27s_algorithm)
     */
    @Deprecated("DES is deprecated, please use DES3 or AES")
    DES(
        "DES", BlockMode.entries.filter { it == BlockMode.GCM }.toTypedArray(), arrayOf(Padding.NONE, Padding.PKCS1),
        intArrayOf(56), false, BlockMode.CBC, Padding.PKCS1,
        arrayOf(Usage.CIPHER)
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
    DH("DH", true, intArrayOf(1024, 2048, 3000, 4096, 8192), arrayOf(Usage.KEY_AGREEMENT)),

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
    ECDH("ECDH", true, intArrayOf(128, 192, 256), arrayOf(Usage.KEY_AGREEMENT));

    /** @suppress **/
    constructor(literal: String, supportedBlockModes: Array<BlockMode>?, supportedPaddings: Array<Padding>?,
                supportedBitSizes: IntArray, asymmetric: Boolean, defaultBlockMode: BlockMode?, defaultPadding: Padding?,
                usages: Array<Usage>) :
            this(literal, supportedBlockModes, supportedPaddings, { value -> supportedBitSizes.contains(value) },
                asymmetric, defaultBlockMode, defaultPadding, usages)

    /** @suppress **/
    constructor(literal: String, asymmetric: Boolean, supportedBitSizes: IntArray, usages: Array<Usage>) :
            this(literal, null, null, { value -> supportedBitSizes.contains(value) }, asymmetric, null, null, usages)

    /** @suppress **/
    constructor(literal: String, asymmetric: Boolean, isBitSizeSupported: (Int) -> Boolean, usages: Array<Usage>) :
            this(literal, null, null, isBitSizeSupported, asymmetric, null, null, usages)

    override fun toString(): String = literal

    companion object {
        /** @suppress **/
        internal fun fromLiteral(literal: String, asymmetric: Boolean): Algorithm? = Algorithm.entries
            .firstOrNull { it.literal == literal && it.asymmetric == asymmetric }
    }

    /**
     * This class indicates the usages for cryptographic algorithms in the Krypton API. Al of these are checked by the
     * API to ensure the correct usage of keys.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     */
    enum class Usage {
        CIPHER,
        KEY_AGREEMENT,
        SIGNATURE
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
    CTR,
    GCM
}

/**
 * This enum represents all paddings support by ciphers.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
enum class Padding(private val literal: String) {
    NONE("NoPadding"),
    PKCS5("PKCS5Padding"),
    PKCS1("PKCS1Padding"),
    OAEP_SHA1_MGF1("OAEPWithSHA-1AndMGF1Padding"),
    OAEP_SHA256_MGF1("OAEPWithSHA-1AndMGF1Padding");

    override fun toString(): String = literal
}