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

package io.karma.evince.krypton.hashes

/**
 * This class is the implementation of digests like the SHA3 family into Kotlin for multiple platforms. It also allows
 * the usage of dynamically sized hash functions like SHAKE.
 *
 * TODO: Implement support for SHAKE etc.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
expect class Digest(string: String, size: Int) : AutoCloseable {
    constructor(type: DigestType, size: Int = type.bitSize / 8)
    fun hash(value: ByteArray): ByteArray
    override fun close()
}

/**
 * This extension method allows to hash the specified string into a byte array.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
fun Digest.hash(value: String): ByteArray = hash(value.encodeToByteArray())

/**
 * This extension method allows to hash the specified string into a string.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
@OptIn(ExperimentalStdlibApi::class)
fun Digest.hashToString(value: String): String = hash(value).toHexString()

/**
 * This extension method allows to hash the specified byte array into a hex string.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
@OptIn(ExperimentalStdlibApi::class)
fun Digest.hashToString(value: ByteArray): String = hash(value).toHexString()

/**
 * This class is listing all officially-supported hash functions provided by the Krypton library itself. It is
 * recommended to use this over the string constructor.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
enum class DigestType(private val literal: String, val bitSize: Int) {
    SHA3_224("SHA3-224", 224),
    SHA3_256("SHA3-256", 256),
    SHA3_384("SHA3-384", 384),
    SHA3_512("SHA3-512", 512),

    @Deprecated("MD5 is not secure and deprecated")
    MD5("MD5", 128),
    @Deprecated("SHA224 is deprecated, please use SHA3-224")
    SHA224("SHA-224", 224),
    @Deprecated("SHA256 is deprecated, please use SHA3-256")
    SHA256("SHA-256", 256),
    @Deprecated("SHA384 is deprecated, please use SHA3-384")
    SHA384("SHA-384", 384),
    @Deprecated("SHA512 is deprecated, please use SHA3-512")
    SHA512("SHA-512", 512);

    override fun toString(): String = literal
}
