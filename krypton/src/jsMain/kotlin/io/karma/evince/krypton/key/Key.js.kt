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

package io.karma.evince.krypton.key

import web.crypto.CryptoKey
import web.crypto.KeyUsage

/**
 * This class is a cross-platform implementation for a key (with support for symmetric and asymmetric keys) that can be
 * used in all parts of the Krypton API like Key generation and signing.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
actual class Key(
    actual val algorithm: String,
    actual val type: Type,
    actual val usages: Array<Usage>,
    internal val internal: CryptoKey
) : AutoCloseable {
    actual override fun close() {}

    /**
     * This enum represents all types available for keys. Symmetric if the key is symmetric and public or private if the key
     * is from an asymmetric algorithm.
     *
     * @author Cedric Hammes
     * @since  08/09/2024
     */
    actual enum class Type {
        SYMMETRIC, PUBLIC, PRIVATE
    }

    /**
     * This enum represents all usages for keys available in Krypton. These usages are used by Android and JS to identify the usages of the
     * key what's part of their security architecture so we try to implement this behavior as best as we can on all platforms compatible
     * with Krypton.
     *
     * @author Cedric Hammes
     * @since  28/09/2024
     */
    actual enum class Usage(actual val supportedTypes: Array<Type>) {
        SIGN(arrayOf(Type.PRIVATE)),
        VERIFY(arrayOf(Type.PUBLIC)),
        ENCRYPT(arrayOf(Type.SYMMETRIC, Type.PUBLIC)),
        DECRYPT(arrayOf(Type.SYMMETRIC, Type.PRIVATE)),
        DERIVE(arrayOf(Type.PRIVATE, Type.PUBLIC));

        fun toWebCrypto(): Array<KeyUsage> = when(this) {
            SIGN -> arrayOf(KeyUsage.sign)
            VERIFY -> arrayOf(KeyUsage.verify)
            ENCRYPT -> arrayOf(KeyUsage.encrypt)
            DECRYPT -> arrayOf(KeyUsage.decrypt)
            DERIVE -> arrayOf(KeyUsage.deriveKey, KeyUsage.deriveBits)
        }
    }
}

internal fun Array<Key.Usage>.toWebCrypto(): Array<KeyUsage> = flatMap { it.toWebCrypto().asIterable() }.toTypedArray()
