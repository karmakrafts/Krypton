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
 * encryption algorithms and key agreements.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
enum class Algorithm(
    private val literal: String,
    internal val supportedBlockModes: Array<BlockMode>?,
    internal val supportedPaddings: Array<Padding>?,
    internal val supportedBitSizes: IntArray,
    internal val asymmetric: Boolean,
    internal val defaultBlockMode: BlockMode?,
    internal val defaultPadding: Padding?
) {
    /**
     * The RSA (Rivest-Shamir-Adleman) algorithm is an asymmetric encryption and signature algorithm created in 1977
     * with a regular key size of 4096 bits.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     *
     * @see [Wikipedia, RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
     */
    RSA("RSA", arrayOf(BlockMode.ECB), arrayOf(Padding.NONE, Padding.PKCS5, Padding.OAEP_SHA1_MGF1,
        Padding.OAEP_SHA256_MGF1), intArrayOf(1024, 2048, 4096, 8192), true,
        BlockMode.ECB, Padding.PKCS5),

    /**
     * Ths AES (Advanced Encryption Standard, also known as Rijndael) block cipher is a symmetric encryption algorithm
     * created in 1998 with a block size of 128 bits.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     *
     * @see [Wikipedia, AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
     */
    AES("AES", BlockMode.entries.toTypedArray(), arrayOf(Padding.NONE, Padding.PKCS1), intArrayOf(128, 192, 256), false,
        BlockMode.CBC, Padding.NONE),

    /**
     * The DES (Data Encryption Standard) block cipher is a symmetric encryption algorithm created in 1975 with a block
     * size of 64 bits. DES can be attacked by bruteforce easily and by multiple cryptanalytic attacks so the algorithm
     * is considered as deprecated and was replaced with Triple-DES and the algorithm AES is recommended for symmetric
     * encryption.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     *
     * @see [Wikipedia, DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
     */
    @Deprecated("DES is deprecated, please use DES3 or AES")
    DES("DES", BlockMode.entries.filter { it == BlockMode.GCM }.toTypedArray(), arrayOf(Padding.NONE, Padding.PKCS1),
        intArrayOf(56), false, BlockMode.CBC, Padding.PKCS1);

    override fun toString(): String = literal

    companion object {
        fun fromLiteral(literal: String): Algorithm? = Algorithm.entries.firstOrNull { it.literal == literal }
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