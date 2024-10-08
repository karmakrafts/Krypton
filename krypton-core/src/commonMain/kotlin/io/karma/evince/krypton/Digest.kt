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

import io.karma.evince.krypton.annotations.UncheckedKryptonAPI

/**
 * This class is the implementation of digests like the SHA3 family into Kotlin for multiple platforms. It also allows
 * the usage of dynamically sized hash functions like SHAKE.
 *
 * TODO: Implement support for SHAKE etc.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
expect class Digest @UncheckedKryptonAPI constructor(string: String, size: Int = 0) : AutoCloseable {
    constructor(algorithm: Algorithm, size: Int = algorithm.defaultBitSize / 8)
    
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
