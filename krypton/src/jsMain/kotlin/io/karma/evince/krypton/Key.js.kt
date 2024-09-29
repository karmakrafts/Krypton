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

import web.crypto.CryptoKey
import web.crypto.KeyUsage

/** @suppress **/
actual class Key(
    actual val algorithm: Algorithm,
    actual val type: Type,
    actual val usages: Array<Usage>,
    internal val internal: CryptoKey
) : AutoCloseable {
    actual override fun close() {} // Not needed on JS

    actual enum class Usage(actual val supportedTypes: Array<Type>, internal val jsUsages: Array<KeyUsage>) {
        ENCRYPT(Type.entries.toTypedArray(), arrayOf(KeyUsage.encrypt)),
        DECRYPT(Type.entries.toTypedArray(), arrayOf(KeyUsage.decrypt)),
        DERIVE(arrayOf(Type.PUBLIC, Type.PRIVATE), arrayOf(KeyUsage.deriveBits, KeyUsage.deriveKey)),
        SIGN(arrayOf(Type.PUBLIC, Type.PRIVATE), arrayOf(KeyUsage.sign)),
        VERIFY(arrayOf(Type.PUBLIC, Type.PRIVATE), arrayOf(KeyUsage.verify))
    }

    actual enum class Type {
        PUBLIC, PRIVATE, OTHER
    }

}

internal fun Array<Key.Usage>.toJsUsages(): Array<KeyUsage> = flatMap { it.jsUsages.asIterable() }.toTypedArray()
